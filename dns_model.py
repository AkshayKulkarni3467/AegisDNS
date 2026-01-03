import os
import re
import random
import logging
from datetime import datetime
from urllib.parse import urlparse
import ipaddress
import numpy as np
import pandas as pd
import requests
import whois
import dns.resolver
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from collections import Counter
import math
import json

# Configuration
RESULTS_DIR = "./results"  # Results directory for metrics
MODEL_DIR = "./dns_model"  # Single directory for everything
BASE_MODEL_PATH = os.path.join(MODEL_DIR, "base_model.pt")
LORA_ADAPTER_PATH = os.path.join(MODEL_DIR, "lora_adapter.pt")
MERGED_MODEL_PATH = os.path.join(MODEL_DIR, "merged_model.pt")
TRAINING_HISTORY_PATH = os.path.join(MODEL_DIR, "training_history.json")
FEED_ARCHIVE_DIR = os.path.join(MODEL_DIR, "feed_snapshots")
BLOCKLIST_PATH = os.path.join(MODEL_DIR, "domain_blocklist.txt")

BENIGN_URL = "https://tranco-list.eu/top-1m.csv.zip"
MALICIOUS_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://phishunt.io/feed.txt"
]

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MAX_FEED_HISTORY = 5

# LoRA hyperparameters
LORA_R = 8  # Rank
LORA_ALPHA = 16  # Scaling factor
LORA_DROPOUT = 0.1

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dns_security_peft")


class LoRALayer(nn.Module):
    """
    LoRA (Low-Rank Adaptation) layer for parameter-efficient fine-tuning
    Decomposes weight updates into low-rank matrices: ΔW = BA where B is r×d, A is d×r
    """
    def __init__(self, in_features, out_features, rank=8, alpha=16, dropout=0.1):
        super().__init__()
        self.rank = rank
        self.alpha = alpha
        self.scaling = alpha / rank
        
        # LoRA matrices (frozen during base training)
        self.lora_A = nn.Parameter(torch.zeros(in_features, rank))
        self.lora_B = nn.Parameter(torch.zeros(rank, out_features))
        self.lora_dropout = nn.Dropout(dropout)
        
        # Initialize A with kaiming uniform, B with zeros
        nn.init.kaiming_uniform_(self.lora_A, a=math.sqrt(5))
        nn.init.zeros_(self.lora_B)
        
    def forward(self, x):
        # LoRA forward: x @ (A @ B) * scaling
        return (self.lora_dropout(x) @ self.lora_A @ self.lora_B) * self.scaling


class LoRALinear(nn.Module):
    """Linear layer with LoRA adapter"""
    def __init__(self, linear_layer, rank=8, alpha=16, dropout=0.1):
        super().__init__()
        self.linear = linear_layer
        self.lora = LoRALayer(
            linear_layer.in_features,
            linear_layer.out_features,
            rank=rank,
            alpha=alpha,
            dropout=dropout
        )
        
    def forward(self, x):
        # Combine frozen linear with LoRA adapter
        return self.linear(x) + self.lora(x)


class DomainFeatureExtractor:
    """Extract comprehensive features from domain names"""
    
    def __init__(self):
        self.char_to_idx = {c: i+1 for i, c in enumerate('abcdefghijklmnopqrstuvwxyz0123456789-._')}
        self.max_domain_len = 253
        self.max_label_len = 63
        
        # Common TLDs for encoding
        self.common_tlds = ['com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 
                           'uk', 'de', 'jp', 'fr', 'au', 'us', 'ru', 'ch', 'it', 'nl', 'se','in']
        self.tld_to_idx = {tld: i for i, tld in enumerate(self.common_tlds)}
        
    def extract_statistical_features(self, domain):
        """Extract statistical features from domain"""
        features = []
        
        # Basic length features (2)
        features.append(len(domain))
        features.append(domain.count('.'))
        
        # Label analysis (4)
        labels = domain.split('.')
        features.append(len(labels))
        features.append(max(len(l) for l in labels) if labels else 0)
        features.append(sum(len(l) for l in labels) / len(labels) if labels else 0)
        features.append(np.std([len(l) for l in labels]) if len(labels) > 1 else 0)
        
        # Character type ratios (3)
        alpha_count = sum(c.isalpha() for c in domain)
        digit_count = sum(c.isdigit() for c in domain)
        special_count = sum(c in '-_.' for c in domain)
        total_chars = len(domain)
        
        features.extend([
            alpha_count / total_chars if total_chars > 0 else 0,
            digit_count / total_chars if total_chars > 0 else 0,
            special_count / total_chars if total_chars > 0 else 0,
        ])
        
        # Entropy calculation (1)
        if domain:
            freq = Counter(domain)
            entropy = -sum((count/len(domain)) * math.log2(count/len(domain)) 
                          for count in freq.values())
            features.append(entropy)
        else:
            features.append(0)
        
        # Consecutive character patterns (2)
        max_consecutive_digits = max((len(list(g)) for k, g in 
                                     __import__('itertools').groupby(domain) if k.isdigit()), 
                                    default=0)
        max_consecutive_consonants = 0
        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')
        current_consonants = 0
        for c in domain.lower():
            if c in consonants:
                current_consonants += 1
                max_consecutive_consonants = max(max_consecutive_consonants, current_consonants)
            else:
                current_consonants = 0
        
        features.extend([max_consecutive_digits, max_consecutive_consonants])
        
        # Vowel/consonant ratio (1)
        vowel_count = sum(c in vowels for c in domain.lower())
        consonant_count = sum(c in consonants for c in domain.lower())
        features.append(vowel_count / (consonant_count + 1))
        
        # Hex pattern (1)
        hex_chars = sum(c in '0123456789abcdef' for c in domain.lower())
        features.append(hex_chars / total_chars if total_chars > 0 else 0)
        
        # TLD features (2)
        tld = labels[-1] if labels else ''
        features.append(self.tld_to_idx.get(tld, len(self.common_tlds)))
        features.append(1 if len(tld) > 4 else 0)  # Unusual TLD length
        
        # Subdomain depth (1)
        features.append(min(len(labels) - 2, 5))  # Cap at 5 for normalization
        
        # Heuristic flags (4)
        features.append(1 if re.search(r'xn--', domain, re.I) else 0)  # Punycode
        features.append(1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain) else 0)  # IP-like
        features.append(1 if re.search(r'[a-z]{4,}\d{3,}|\d{4,}[a-z]{4,}', domain, re.I) else 0)  # Random pattern
        features.append(1 if any(len(l) > 20 for l in labels) else 0)  # Long label
        
        # Total: 2+4+3+1+2+1+1+2+1+4 = 21 features
        return np.array(features, dtype=np.float32)
    
    def domain_to_sequence(self, domain, max_len=100):
        """Convert domain to character sequence"""
        seq = [self.char_to_idx.get(c.lower(), 0) for c in domain[:max_len]]
        # Pad or truncate
        if len(seq) < max_len:
            seq += [0] * (max_len - len(seq))
        return np.array(seq[:max_len], dtype=np.int64)


class DNSDataset(Dataset):
    """PyTorch Dataset for DNS domain classification"""
    
    def __init__(self, domains, labels, feature_extractor):
        self.domains = domains
        self.labels = labels
        self.feature_extractor = feature_extractor
        
    def __len__(self):
        return len(self.domains)
    
    def __getitem__(self, idx):
        domain = self.domains[idx]
        label = self.labels[idx]
        
        # Extract features
        stat_features = self.feature_extractor.extract_statistical_features(domain)
        seq_features = self.feature_extractor.domain_to_sequence(domain)
        
        return {
            'statistical': torch.FloatTensor(stat_features),
            'sequence': torch.LongTensor(seq_features),
            'label': torch.LongTensor([label])
        }


class DNSSecurityModel(nn.Module):
    """
    Hybrid architecture combining:
    1. CNN for character-level patterns
    2. Statistical feature processing
    3. LoRA adapters for efficient fine-tuning
    """
    
    def __init__(self, vocab_size=40, embedding_dim=32, num_filters=128, 
                 stat_features=21, hidden_dim=256, dropout=0.3, use_lora=False,
                 lora_r=8, lora_alpha=16, lora_dropout=0.1):
        super(DNSSecurityModel, self).__init__()
        
        self.use_lora = use_lora
        
        # Character embedding layer (not adapted with LoRA - relatively small)
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        
        # Multi-scale CNN for character patterns
        self.conv1 = nn.Conv1d(embedding_dim, num_filters, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(embedding_dim, num_filters, kernel_size=5, padding=2)
        self.conv3 = nn.Conv1d(embedding_dim, num_filters, kernel_size=7, padding=3)
        
        # Batch normalization
        self.bn1 = nn.BatchNorm1d(num_filters * 3)
        
        # Statistical feature processing with LoRA
        self.stat_fc1 = nn.Linear(stat_features, 128)
        self.stat_bn = nn.BatchNorm1d(128)
        self.stat_fc2 = nn.Linear(128, 64)
        
        # Combined processing with LoRA on larger layers
        self.fc1 = nn.Linear(num_filters * 3 + 64, hidden_dim)
        self.bn2 = nn.BatchNorm1d(hidden_dim)
        self.dropout1 = nn.Dropout(dropout)
        
        self.fc2 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.bn3 = nn.BatchNorm1d(hidden_dim // 2)
        self.dropout2 = nn.Dropout(dropout)
        
        self.fc3 = nn.Linear(hidden_dim // 2, 2)
        
        self.relu = nn.ReLU()
        
        # Store original layers for LoRA wrapping
        self.lora_layers = []
        
        if use_lora:
            self._apply_lora(lora_r, lora_alpha, lora_dropout)
    
    def _apply_lora(self, rank, alpha, dropout):
        """Apply LoRA adapters to linear layers"""
        # Wrap large linear layers with LoRA
        self.stat_fc1 = LoRALinear(self.stat_fc1, rank, alpha, dropout)
        self.stat_fc2 = LoRALinear(self.stat_fc2, rank, alpha, dropout)
        self.fc1 = LoRALinear(self.fc1, rank, alpha, dropout)
        self.fc2 = LoRALinear(self.fc2, rank, alpha, dropout)
        self.fc3 = LoRALinear(self.fc3, rank, alpha, dropout)
        
        self.lora_layers = [self.stat_fc1, self.stat_fc2, self.fc1, self.fc2, self.fc3]
        
        logger.info("LoRA adapters applied to model")
    
    def freeze_base_model(self):
        """Freeze all parameters except LoRA adapters"""
        for name, param in self.named_parameters():
            if 'lora' not in name:
                param.requires_grad = False
        
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        total = sum(p.numel() for p in self.parameters())
        logger.info(f"Trainable params: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")
    
    def merge_lora_weights(self):
        """Merge LoRA weights into base model (for inference optimization)"""
        if not self.use_lora:
            return
        
        for layer in self.lora_layers:
            if isinstance(layer, LoRALinear):
                # Merge: W_new = W_base + scaling * (B @ A)
                lora_weight = (layer.lora.lora_A @ layer.lora.lora_B) * layer.lora.scaling
                layer.linear.weight.data += lora_weight.T
                
        logger.info("LoRA weights merged into base model")
    
    def forward(self, sequence, statistical):
        # Process sequence through embedding
        embedded = self.embedding(sequence)
        embedded = embedded.transpose(1, 2)
        
        # Multi-scale convolutions
        conv1_out = self.relu(self.conv1(embedded))
        conv2_out = self.relu(self.conv2(embedded))
        conv3_out = self.relu(self.conv3(embedded))
        
        # Concatenate multi-scale features
        conv_out = torch.cat([conv1_out, conv2_out, conv3_out], dim=1)
        conv_out = self.bn1(conv_out)
        
        # Global max pooling
        pooled = torch.max(conv_out, dim=2)[0]
        
        # Process statistical features
        stat_out = self.relu(self.stat_bn(self.stat_fc1(statistical)))
        stat_out = self.relu(self.stat_fc2(stat_out))
        
        # Combine features
        combined = torch.cat([pooled, stat_out], dim=1)
        
        # Final classification layers
        x = self.dropout1(self.relu(self.bn2(self.fc1(combined))))
        x = self.dropout2(self.relu(self.bn3(self.fc2(x))))
        logits = self.fc3(x)
        
        return logits


class TrainingHistory:
    """Track training history and seen domains"""
    def __init__(self, path=TRAINING_HISTORY_PATH):
        self.path = path
        self.history = self._load()
    
    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, 'r') as f:
                return json.load(f)
        return {
            'seen_domains': set(),
            'training_runs': [],
            'total_samples_trained': 0
        }
    
    def save(self):
        # Convert set to list for JSON serialization
        data = self.history.copy()
        data['seen_domains'] = list(data['seen_domains'])
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_training_run(self, benign_count, malicious_count, metrics, is_incremental):
        self.history['training_runs'].append({
            'timestamp': datetime.now().isoformat(),
            'benign_samples': benign_count,
            'malicious_samples': malicious_count,
            'metrics': metrics,
            'is_incremental': is_incremental
        })
        self.history['total_samples_trained'] += (benign_count + malicious_count)
    
    def add_seen_domains(self, domains):
        if isinstance(self.history['seen_domains'], list):
            self.history['seen_domains'] = set(self.history['seen_domains'])
        self.history['seen_domains'].update(domains)
    
    def get_unseen_domains(self, domains):
        if isinstance(self.history['seen_domains'], list):
            self.history['seen_domains'] = set(self.history['seen_domains'])
        return [d for d in domains if d not in self.history['seen_domains']]


def fetch_tranco(limit=100000):
    """Fetch benign domains from Tranco"""
    try:
        df = pd.read_csv(BENIGN_URL, compression="zip", header=None, names=["rank", "domain"])
        return df["domain"].head(limit).astype(str).tolist()
    except Exception as e:
        logger.warning(f"Tranco fetch failed: {e} — using fallback")
        words = ["home","login","account","cdn","service","api","static","docs","secure","portal",
                "mail", "shop", "store", "blog", "news", "support", "help", "app"]
        tlds = ["com","net","org","io","dev","co.uk"]
        return [f"{random.choice(words)}{random.choice(words)}.{random.choice(tlds)}" 
                for _ in range(min(limit, 20000))]


def fetch_threat_feeds():
    """Fetch malicious domains from threat feeds"""
    malicious = set()
    
    for feed in MALICIOUS_FEEDS:
        try:
            r = requests.get(feed, timeout=15)
            if r.status_code != 200:
                continue
            
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                try:
                    parsed = urlparse(line if "://" in line else f"http://{line}")
                    host = parsed.hostname
                    if not host:
                        continue
                    
                    host = host.lower().rstrip(".")
                    
                    # # Skip IPs
                    # try:
                    #     ipaddress.ip_address(host)
                    #     continue
                    # except ValueError:
                    #     pass
                    
                    malicious.add(host)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"Feed fetch error {feed}: {e}")
            continue
    
    return list(malicious)

def save_training_metrics(train_metrics, val_metrics, model_type="base", timestamp=None):
    """Save training metrics to results directory"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    results = {
        'timestamp': timestamp,
        'model_type': model_type,
        'device': DEVICE,
        'train_metrics': train_metrics,
        'val_metrics': val_metrics
    }
    
    # Save as JSON
    json_path = os.path.join(RESULTS_DIR, f"{model_type}_metrics_{timestamp}.json")
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"✓ Saved metrics to {json_path}")
    
    # Save as CSV for easy viewing
    csv_path = os.path.join(RESULTS_DIR, f"{model_type}_metrics_{timestamp}.csv")
    metrics_df = pd.DataFrame([
        {
            'split': 'train',
            'accuracy': train_metrics.get('accuracy', 0),
            'precision': train_metrics.get('precision', 0),
            'recall': train_metrics.get('recall', 0),
            'f1': train_metrics.get('f1', 0),
            'auc': train_metrics.get('auc', 0)
        },
        {
            'split': 'validation',
            'accuracy': val_metrics.get('accuracy', 0),
            'precision': val_metrics.get('precision', 0),
            'recall': val_metrics.get('recall', 0),
            'f1': val_metrics.get('f1', 0),
            'auc': val_metrics.get('auc', 0)
        }
    ])
    metrics_df.to_csv(csv_path, index=False)
    logger.info(f"✓ Saved metrics to {csv_path}")
    
    return json_path, csv_path

def save_feed_snapshot(benign_list, malicious_list):
    """Save domain lists as timestamped snapshots"""
    os.makedirs(FEED_ARCHIVE_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    benign_path = os.path.join(FEED_ARCHIVE_DIR, f"benign_{ts}.csv")
    malicious_path = os.path.join(FEED_ARCHIVE_DIR, f"malicious_{ts}.csv")
    
    pd.DataFrame(benign_list, columns=["domain"]).to_csv(benign_path, index=False)
    pd.DataFrame(malicious_list, columns=["domain"]).to_csv(malicious_path, index=False)
    
    # Keep only recent snapshots
    all_files = sorted(
        [f for f in os.listdir(FEED_ARCHIVE_DIR) if f.endswith(".csv")],
        key=lambda f: os.path.getmtime(os.path.join(FEED_ARCHIVE_DIR, f)),
        reverse=True,
    )
    
    for old in all_files[MAX_FEED_HISTORY * 2:]:
        os.remove(os.path.join(FEED_ARCHIVE_DIR, old))
    
    logger.info(f"Saved feed snapshot — benign: {benign_path}, malicious: {malicious_path}")


def train_base_model(epochs=50, batch_size=64, learning_rate=0.001):
    """Train the base DNS security model (full training, no LoRA)"""
    logger.info("=" * 60)
    logger.info("TRAINING BASE MODEL (Full Parameters)")
    logger.info("=" * 60)
    
    # Create directories
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(FEED_ARCHIVE_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Fetch ALL available data (no limit)
    logger.info("Fetching benign domains from Tranco...")
    benign = fetch_tranco(limit=1000000)  # Fetch up to 1M
    logger.info(f"Fetched {len(benign)} benign domains")
    
    logger.info("Fetching malicious domains from threat feeds...")
    malicious = fetch_threat_feeds()
    logger.info(f"Fetched {len(malicious)} malicious domains")
    
    save_feed_snapshot(benign, malicious)
    
    if len(malicious) < 100:
        logger.error("Insufficient malicious samples")
        return None
    
    # Balance dataset to min(benign, malicious) - NO max_samples limit
    min_samples = min(len(benign), len(malicious))
    
    logger.info(f"Balancing dataset to {min_samples} samples per class")
    
    benign = random.sample(benign, min_samples)
    malicious = random.sample(malicious, min_samples)
    
    # Prepare data
    domains = benign + malicious
    labels = [0] * len(benign) + [1] * len(malicious)
    
    logger.info(f"Total training samples: {len(domains)} ({len(benign)} benign + {len(malicious)} malicious)")
    
    # Split
    train_domains, val_domains, train_labels, val_labels = train_test_split(
        domains, labels, test_size=0.15, random_state=42, stratify=labels
    )
    
    logger.info(f"Training samples: {len(train_domains)}, Validation samples: {len(val_domains)}")
    
    # Create datasets
    feature_extractor = DomainFeatureExtractor()
    train_dataset = DNSDataset(train_domains, train_labels, feature_extractor)
    val_dataset = DNSDataset(val_domains, val_labels, feature_extractor)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    
    # Initialize model WITHOUT LoRA
    model = DNSSecurityModel(use_lora=False).to(DEVICE)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', patience=3, factor=0.5)
    
    best_f1 = 0
    patience_counter = 0
    max_patience = 30
    
    # Store metrics history per epoch
    epoch_history = []
    
    logger.info(f"Starting training for {epochs} epochs...")
    logger.info(f"Device: {DEVICE}")
    logger.info(f"Batch size: {batch_size}")
    logger.info(f"Learning rate: {learning_rate}")
    
    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0
        train_batches = 0
        train_preds = []
        train_true = []
        train_probs = []
        
        for batch in train_loader:
            optimizer.zero_grad()
            
            seq = batch['sequence'].to(DEVICE)
            stat = batch['statistical'].to(DEVICE)
            labels_batch = batch['label'].squeeze().to(DEVICE)
            
            outputs = model(seq, stat)
            loss = criterion(outputs, labels_batch)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            train_loss += loss.item()
            train_batches += 1
            
            # Collect predictions for train metrics
            with torch.no_grad():
                probs = torch.softmax(outputs, dim=1)
                preds = torch.argmax(outputs, dim=1)
                train_preds.extend(preds.cpu().numpy())
                train_true.extend(labels_batch.cpu().numpy())
                train_probs.extend(probs[:, 1].cpu().numpy())
        
        avg_train_loss = train_loss / train_batches
        
        # Calculate training metrics
        train_accuracy = accuracy_score(train_true, train_preds)
        train_f1 = f1_score(train_true, train_preds)
        train_precision = precision_score(train_true, train_preds)
        train_recall = recall_score(train_true, train_preds)
        train_auc = roc_auc_score(train_true, train_probs)
        
        # Validation
        model.eval()
        val_preds = []
        val_true = []
        val_probs = []
        
        with torch.no_grad():
            for batch in val_loader:
                seq = batch['sequence'].to(DEVICE)
                stat = batch['statistical'].to(DEVICE)
                labels_batch = batch['label'].squeeze().to(DEVICE)
                
                outputs = model(seq, stat)
                probs = torch.softmax(outputs, dim=1)
                preds = torch.argmax(outputs, dim=1)
                
                val_preds.extend(preds.cpu().numpy())
                val_true.extend(labels_batch.cpu().numpy())
                val_probs.extend(probs[:, 1].cpu().numpy())
        
        # Validation metrics
        val_accuracy = accuracy_score(val_true, val_preds)
        val_f1 = f1_score(val_true, val_preds)
        val_precision = precision_score(val_true, val_preds)
        val_recall = recall_score(val_true, val_preds)
        val_auc = roc_auc_score(val_true, val_probs)
        
        # Store epoch metrics
        epoch_history.append({
            'epoch': epoch + 1,
            'train_loss': avg_train_loss,
            'train_accuracy': train_accuracy,
            'train_precision': train_precision,
            'train_recall': train_recall,
            'train_f1': train_f1,
            'train_auc': train_auc,
            'val_accuracy': val_accuracy,
            'val_precision': val_precision,
            'val_recall': val_recall,
            'val_f1': val_f1,
            'val_auc': val_auc
        })
        
        logger.info(f"Epoch {epoch+1}/{epochs} - Loss: {avg_train_loss:.4f}")
        logger.info(f"  Train - Acc: {train_accuracy:.4f}, F1: {train_f1:.4f}, "
                   f"Prec: {train_precision:.4f}, Rec: {train_recall:.4f}, AUC: {train_auc:.4f}")
        logger.info(f"  Val   - Acc: {val_accuracy:.4f}, F1: {val_f1:.4f}, "
                   f"Prec: {val_precision:.4f}, Rec: {val_recall:.4f}, AUC: {val_auc:.4f}")
        
        scheduler.step(val_f1)
        
        # Save best model
        if val_f1 > best_f1:
            best_f1 = val_f1
            patience_counter = 0
            
            # Save without pickled objects - only tensors and metrics
            torch.save({
                'model_state_dict': model.state_dict(),
                'metrics': {
                    'train_accuracy': train_accuracy,
                    'train_precision': train_precision,
                    'train_recall': train_recall,
                    'train_f1': train_f1,
                    'train_auc': train_auc,
                    'val_accuracy': val_accuracy,
                    'val_precision': val_precision,
                    'val_recall': val_recall,
                    'val_f1': val_f1,
                    'val_auc': val_auc
                }
            }, BASE_MODEL_PATH)
            
            logger.info(f"✓ Saved best BASE model with Val F1: {val_f1:.4f}")
        else:
            patience_counter += 1
            if patience_counter >= max_patience:
                logger.info(f"Early stopping triggered at epoch {epoch+1}")
                break
    
    # Save epoch-by-epoch history
    epoch_history_path = os.path.join(RESULTS_DIR, f"base_epoch_history_{timestamp}.csv")
    pd.DataFrame(epoch_history).to_csv(epoch_history_path, index=False)
    logger.info(f"✓ Saved epoch history to {epoch_history_path}")
    
    # Save final metrics
    final_train_metrics = {
        'accuracy': train_accuracy,
        'precision': train_precision,
        'recall': train_recall,
        'f1': train_f1,
        'auc': train_auc,
        'loss': avg_train_loss
    }
    
    final_val_metrics = {
        'accuracy': val_accuracy,
        'precision': val_precision,
        'recall': val_recall,
        'f1': val_f1,
        'auc': val_auc
    }
    
    save_training_metrics(final_train_metrics, final_val_metrics, 
                         model_type="base", timestamp=timestamp)
    
    # Save training history
    history = TrainingHistory()
    history.add_seen_domains(domains)
    history.add_training_run(len(benign), len(malicious), {
        'train_accuracy': train_accuracy,
        'train_f1': train_f1,
        'train_precision': train_precision,
        'train_recall': train_recall,
        'train_auc': train_auc,
        'val_accuracy': val_accuracy,
        'val_f1': val_f1,
        'val_precision': val_precision,
        'val_recall': val_recall,
        'val_auc': val_auc
    }, is_incremental=False)
    history.save()
    
    logger.info("=" * 60)
    logger.info("BASE MODEL TRAINING COMPLETE")
    logger.info(f"Best Val F1 Score: {best_f1:.4f}")
    logger.info(f"Total samples trained: {len(domains)}")
    logger.info(f"Results saved to: {RESULTS_DIR}")
    logger.info("=" * 60)
    
    return model, feature_extractor

def incremental_update(epochs=20, batch_size=64, learning_rate=0.0001, 
                       lora_r=LORA_R, lora_alpha=LORA_ALPHA, lora_dropout=LORA_DROPOUT):
    """
    Incremental update using LoRA - ONLY trains on NEW domains
    This is what you run daily!
    """
    logger.info("=" * 60)
    logger.info("INCREMENTAL UPDATE WITH LoRA (Daily Run)")
    logger.info("=" * 60)
    
    # Ensure directories exist
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(FEED_ARCHIVE_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Load training history
    history = TrainingHistory()
    
    # Fetch new data
    logger.info("Fetching latest threat feeds...")
    benign = fetch_tranco(limit=100000)
    malicious = fetch_threat_feeds()
    
    # Filter to only NEW domains
    new_benign = history.get_unseen_domains(benign)
    new_malicious = history.get_unseen_domains(malicious)
    
    logger.info(f"New domains - Benign: {len(new_benign)}, Malicious: {len(new_malicious)}")
    
    if len(new_malicious) < 10:
        logger.warning("Fewer than 10 new malicious domains - skipping update")
        return None, None
    
    save_feed_snapshot(new_benign, new_malicious)
    
    # Balance new data
    min_samples = min(len(new_benign), len(new_malicious), 10000)
    if min_samples < 10:
        logger.warning("Insufficient new samples for meaningful update")
        return None, None
    
    new_benign = random.sample(new_benign, min_samples)
    new_malicious = random.sample(new_malicious, min_samples)
    
    domains = new_benign + new_malicious
    labels = [0] * len(new_benign) + [1] * len(new_malicious)
    
    # Split
    train_domains, val_domains, train_labels, val_labels = train_test_split(
        domains, labels, test_size=0.15, random_state=42, stratify=labels
    )
    
    logger.info(f"Training on {len(train_domains)} NEW samples")
    
    if not os.path.exists(BASE_MODEL_PATH):
        logger.error("Base model not found! Run train_base_model() first")
        return None, None

    # Load with weights_only=True (new format only)
    checkpoint = torch.load(BASE_MODEL_PATH, map_location=DEVICE, weights_only=True)

    # Always recreate feature extractor (don't unpickle)
    feature_extractor = DomainFeatureExtractor()

    logger.info("Loaded base model (weights only)")
    
    # Create model with LoRA
    model = DNSSecurityModel(
        use_lora=True, 
        lora_r=lora_r, 
        lora_alpha=lora_alpha, 
        lora_dropout=lora_dropout
    ).to(DEVICE)
    
    # Load base weights
    model.load_state_dict(checkpoint['model_state_dict'], strict=False)
    
    # Freeze base model, only train LoRA adapters
    model.freeze_base_model()
    
    # Create datasets
    train_dataset = DNSDataset(train_domains, train_labels, feature_extractor)
    val_dataset = DNSDataset(val_domains, val_labels, feature_extractor)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    
    criterion = nn.CrossEntropyLoss()
    # Lower learning rate for fine-tuning
    optimizer = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad], 
        lr=learning_rate, 
        weight_decay=0.01
    )
    
    best_f1 = 0
    
    # Store metrics history per epoch
    epoch_history = []
    
    logger.info(f"Starting incremental training for {epochs} epochs...")
    logger.info(f"Device: {DEVICE}")
    logger.info(f"Batch size: {batch_size}")
    logger.info(f"Learning rate: {learning_rate}")
    logger.info(f"LoRA config - Rank: {lora_r}, Alpha: {lora_alpha}, Dropout: {lora_dropout}")
    
    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0
        train_batches = 0
        train_preds = []
        train_true = []
        train_probs = []
        
        for batch in train_loader:
            optimizer.zero_grad()
            
            seq = batch['sequence'].to(DEVICE)
            stat = batch['statistical'].to(DEVICE)
            labels_batch = batch['label'].squeeze().to(DEVICE)
            
            outputs = model(seq, stat)
            loss = criterion(outputs, labels_batch)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            train_loss += loss.item()
            train_batches += 1
            
            # Collect predictions for train metrics
            with torch.no_grad():
                probs = torch.softmax(outputs, dim=1)
                preds = torch.argmax(outputs, dim=1)
                train_preds.extend(preds.cpu().numpy())
                train_true.extend(labels_batch.cpu().numpy())
                train_probs.extend(probs[:, 1].cpu().numpy())
        
        avg_train_loss = train_loss / train_batches
        
        # Calculate training metrics
        train_accuracy = accuracy_score(train_true, train_preds)
        train_f1 = f1_score(train_true, train_preds)
        train_precision = precision_score(train_true, train_preds)
        train_recall = recall_score(train_true, train_preds)
        train_auc = roc_auc_score(train_true, train_probs)
        
        # Validation
        model.eval()
        val_preds = []
        val_true = []
        val_probs = []
        
        with torch.no_grad():
            for batch in val_loader:
                seq = batch['sequence'].to(DEVICE)
                stat = batch['statistical'].to(DEVICE)
                labels_batch = batch['label'].squeeze().to(DEVICE)
                
                outputs = model(seq, stat)
                probs = torch.softmax(outputs, dim=1)
                preds = torch.argmax(outputs, dim=1)
                
                val_preds.extend(preds.cpu().numpy())
                val_true.extend(labels_batch.cpu().numpy())
                val_probs.extend(probs[:, 1].cpu().numpy())
        
        # Validation metrics
        val_accuracy = accuracy_score(val_true, val_preds)
        val_f1 = f1_score(val_true, val_preds)
        val_precision = precision_score(val_true, val_preds)
        val_recall = recall_score(val_true, val_preds)
        val_auc = roc_auc_score(val_true, val_probs)
        
        # Store epoch metrics
        epoch_history.append({
            'epoch': epoch + 1,
            'train_loss': avg_train_loss,
            'train_accuracy': train_accuracy,
            'train_precision': train_precision,
            'train_recall': train_recall,
            'train_f1': train_f1,
            'train_auc': train_auc,
            'val_accuracy': val_accuracy,
            'val_precision': val_precision,
            'val_recall': val_recall,
            'val_f1': val_f1,
            'val_auc': val_auc
        })
        
        logger.info(f"Epoch {epoch+1}/{epochs} - Loss: {avg_train_loss:.4f}")
        logger.info(f"  Train - Acc: {train_accuracy:.4f}, F1: {train_f1:.4f}, "
                   f"Prec: {train_precision:.4f}, Rec: {train_recall:.4f}, AUC: {train_auc:.4f}")
        logger.info(f"  Val   - Acc: {val_accuracy:.4f}, F1: {val_f1:.4f}, "
                   f"Prec: {val_precision:.4f}, Rec: {val_recall:.4f}, AUC: {val_auc:.4f}")
        
        if val_f1 > best_f1:
            best_f1 = val_f1
    
    # Save epoch-by-epoch history
    epoch_history_path = os.path.join(RESULTS_DIR, f"incremental_epoch_history_{timestamp}.csv")
    pd.DataFrame(epoch_history).to_csv(epoch_history_path, index=False)
    logger.info(f"✓ Saved epoch history to {epoch_history_path}")
    
    # Save LoRA adapter
    lora_state = {name: param for name, param in model.named_parameters() if 'lora' in name}
    torch.save({
        'lora_state_dict': lora_state,
        'lora_config': {
            'rank': lora_r,
            'alpha': lora_alpha,
            'dropout': lora_dropout
        },
        'metrics': {
            'train_accuracy': train_accuracy,
            'train_precision': train_precision,
            'train_recall': train_recall,
            'train_f1': train_f1,
            'train_auc': train_auc,
            'val_accuracy': val_accuracy,
            'val_precision': val_precision,
            'val_recall': val_recall,
            'val_f1': val_f1,
            'val_auc': val_auc
        }
    }, LORA_ADAPTER_PATH)
    
    logger.info(f"✓ Saved LoRA adapter with Val F1: {val_f1:.4f}")
    
    # Merge and save for inference
    logger.info("Merging LoRA weights into base model...")
    model.merge_lora_weights()
    
    # Save merged model (no LoRA dependencies needed for inference)
    torch.save({
        'model_state_dict': model.state_dict(),
        'metrics': {
            'train_accuracy': train_accuracy,
            'train_precision': train_precision,
            'train_recall': train_recall,
            'train_f1': train_f1,
            'train_auc': train_auc,
            'val_accuracy': val_accuracy,
            'val_precision': val_precision,
            'val_recall': val_recall,
            'val_f1': val_f1,
            'val_auc': val_auc
        }
    }, MERGED_MODEL_PATH)
    
    logger.info(f"✓ Saved merged model to {MERGED_MODEL_PATH}")
    
    # Save final metrics
    final_train_metrics = {
        'accuracy': train_accuracy,
        'precision': train_precision,
        'recall': train_recall,
        'f1': train_f1,
        'auc': train_auc,
        'loss': avg_train_loss
    }
    
    final_val_metrics = {
        'accuracy': val_accuracy,
        'precision': val_precision,
        'recall': val_recall,
        'f1': val_f1,
        'auc': val_auc
    }
    
    save_training_metrics(final_train_metrics, final_val_metrics, 
                         model_type="incremental", timestamp=timestamp)
    
    # Update history
    history.add_seen_domains(domains)
    history.add_training_run(len(new_benign), len(new_malicious), {
        'train_accuracy': train_accuracy,
        'train_f1': train_f1,
        'train_precision': train_precision,
        'train_recall': train_recall,
        'train_auc': train_auc,
        'val_accuracy': val_accuracy,
        'val_f1': val_f1,
        'val_precision': val_precision,
        'val_recall': val_recall,
        'val_auc': val_auc
    }, is_incremental=True)
    history.save()
    
    logger.info("=" * 60)
    logger.info("INCREMENTAL UPDATE COMPLETE")
    logger.info(f"Best Val F1 Score: {best_f1:.4f}")
    logger.info(f"Total domains seen: {len(history.history['seen_domains'])}")
    logger.info(f"Results saved to: {RESULTS_DIR}")
    logger.info("=" * 60)
    
    return model, feature_extractor


def load_model(prefer_merged=True):
    """Load model for inference"""
    # Try merged model first (fastest, no LoRA overhead)
    if prefer_merged and os.path.exists(MERGED_MODEL_PATH):
        logger.info(f"Loading merged model from {MERGED_MODEL_PATH}")
        try:
            # Try with weights_only=True first (safer)
            checkpoint = torch.load(MERGED_MODEL_PATH, map_location=DEVICE, weights_only=True)
        except Exception:
            # Fallback for older saved models
            checkpoint = torch.load(MERGED_MODEL_PATH, map_location=DEVICE, weights_only=False)
        
        model = DNSSecurityModel(use_lora=False).to(DEVICE)
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        
        # Recreate feature extractor instead of unpickling
        feature_extractor = DomainFeatureExtractor()
        
        logger.info(f"Model loaded with metrics: {checkpoint.get('metrics', {})}")
        return model, feature_extractor
    
    # Fall back to base model
    if os.path.exists(BASE_MODEL_PATH):
        logger.info(f"Loading base model from {BASE_MODEL_PATH}")
        try:
            # Try with weights_only=True first (safer)
            checkpoint = torch.load(BASE_MODEL_PATH, map_location=DEVICE, weights_only=True)
        except Exception:
            # Fallback for older saved models
            checkpoint = torch.load(BASE_MODEL_PATH, map_location=DEVICE, weights_only=False)
        
        model = DNSSecurityModel(use_lora=False).to(DEVICE)
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        
        # Recreate feature extractor instead of unpickling
        feature_extractor = DomainFeatureExtractor()
        
        logger.info(f"Model loaded with metrics: {checkpoint.get('metrics', {})}")
        return model, feature_extractor
    
    raise FileNotFoundError("No trained model found! Run train_base_model() first")

def predict_domain(domain, model, feature_extractor):
    """Predict if domain is malicious"""
    model.eval()
    
    domain = domain.strip().lower().rstrip(".")
    
    stat_features = feature_extractor.extract_statistical_features(domain)
    seq_features = feature_extractor.domain_to_sequence(domain)
    
    stat_tensor = torch.FloatTensor(stat_features).unsqueeze(0).to(DEVICE)
    seq_tensor = torch.LongTensor(seq_features).unsqueeze(0).to(DEVICE)
    
    with torch.no_grad():
        outputs = model(seq_tensor, stat_tensor)
        probs = torch.softmax(outputs, dim=1)
        malicious_prob = probs[0, 1].item()
    
    return malicious_prob


def dns_action(qname, model, feature_extractor, blocklist, ml_threshold=0.7):
    """Make DNS decision for a query"""
    qname = qname.strip().lower().rstrip(".")
    
    # Check blocklist
    if qname in blocklist:
        return {
            "domain": qname,
            "decision": "BLOCKED",
            "score": 1.00,
            "reason": "blocklist:domain"
        }
    
    # Basic heuristics
    if re.search(r'^\d{1,3}(\.\d{1,3}){3}', qname):
        return {
            "domain": qname,
            "decision": "BLOCKED",
            "score": 0.98,
            "reason": "heuristic:ip_address"
        }
    
    if re.search(r'xn--', qname, re.I):
        return {
            "domain": qname,
            "decision": "BLOCKED",
            "score": 0.95,
            "reason": "heuristic:punycode"
        }
    
    # ML prediction
    try:
        score = predict_domain(qname, model, feature_extractor)
        
        if score >= ml_threshold:
            decision = "BLOCKED"
            reason = "ml:malicious"
        elif score >= ml_threshold * 0.5:
            decision = "FLAGGED"
            reason = "ml:suspicious"
        else:
            decision = "ALLOWED"
            reason = "ml:benign"
        
        return {
            "domain": qname,
            "decision": decision,
            "score": float(score),
            "reason": reason
        }
    except Exception as e:
        logger.error(f"Prediction error for {qname}: {e}")
        return {
            "domain": qname,
            "decision": "ALLOWED",
            "score": 0.0,
            "reason": "error:fallback_allow"
        }


# Main execution
if __name__ == "__main__":
    import sys
    
    # Ensure model directory exists
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "train_base":
            logger.info("Training base model from scratch...")
            train_base_model()
            
        elif command == "update":
            logger.info("Running incremental update (daily)...")
            incremental_update()
            
        elif command == "test":
            logger.info("Testing model...")
            model, fe = load_model()
            
            test_domains = [
                "google.com",
                "facebook.com",
                "xn--80ak6aa92e.com",
                "secure-login-verify123456.com",
                "amazon.com",
                "a8f3d2e9b1c4.tk",
                "paypal-security-update.info",
                "microsoft-support.xyz"
            ]
            
            print("\n" + "=" * 70)
            print("DOMAIN CLASSIFICATION RESULTS")
            print("=" * 70)
            for domain in test_domains:
                result = dns_action(domain, model, fe, set())
                print(f"{domain:40} -> {result['decision']:8} (score: {result['score']:.3f}) - {result['reason']}")
            print("=" * 70)
            
        elif command == "info":
            # Show model directory info
            print("\n" + "=" * 70)
            print(f"DNS MODEL DIRECTORY: {os.path.abspath(MODEL_DIR)}")
            print("=" * 70)
            
            files = {
                "Base Model": BASE_MODEL_PATH,
                "LoRA Adapter": LORA_ADAPTER_PATH,
                "Merged Model": MERGED_MODEL_PATH,
                "Training History": TRAINING_HISTORY_PATH,
                "Feed Snapshots": FEED_ARCHIVE_DIR,
                "Blocklist": BLOCKLIST_PATH
            }
            
            for name, path in files.items():
                if os.path.exists(path):
                    if os.path.isdir(path):
                        count = len(os.listdir(path))
                        print(f"✓ {name:20} -> {path} ({count} files)")
                    else:
                        size = os.path.getsize(path) / (1024 * 1024)  # MB
                        print(f"✓ {name:20} -> {path} ({size:.2f} MB)")
                else:
                    print(f"✗ {name:20} -> {path} (not found)")
            
            # Show training history summary
            if os.path.exists(TRAINING_HISTORY_PATH):
                history = TrainingHistory()
                print("\n" + "-" * 70)
                print("TRAINING HISTORY:")
                print(f"  Total domains seen: {len(history.history.get('seen_domains', []))}")
                print(f"  Training runs: {len(history.history.get('training_runs', []))}")
                
                if history.history.get('training_runs'):
                    last_run = history.history['training_runs'][-1]
                    print(f"  Last update: {last_run.get('timestamp', 'N/A')}")
                    print(f"  Last F1 score: {last_run.get('metrics', {}).get('f1', 'N/A'):.4f}")
                    print(f"  Incremental: {last_run.get('is_incremental', False)}")
            print("=" * 70 + "\n")
            
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python dns_model.py train_base  - Train base model (run once)")
            print("  python dns_model.py update      - Incremental update (run daily)")
            print("  python dns_model.py test        - Test model")
            print("  python dns_model.py info        - Show model directory info")
    else:
        print("DNS Security Model with LoRA PEFT")
        print(f"\nModel Directory: {os.path.abspath(MODEL_DIR)}")
        print("\nUsage:")
        print("  python dns_model.py train_base  - Train base model (run ONCE initially)")
        print("  python dns_model.py update      - Incremental update (run DAILY)")
        print("  python dns_model.py test        - Test model predictions")
        print("  python dns_model.py info        - Show model directory info")