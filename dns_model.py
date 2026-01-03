import os
import re
import json
import time
import random
import logging
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter
import ipaddress

import pandas as pd
import requests
import tldextract
import whois
import dns.resolver

import torch
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)
from peft import LoraConfig, get_peft_model, PeftModel



BASE_MODEL = "distilbert-base-uncased"
MODEL_DIR = "./dns_model_peft"                 
MERGED_MODEL_DIR = "./dns_model_merged"       
BLOCKLIST_PATH = "domain_blocklist.txt"
BENIGN_URL = "https://tranco-list.eu/top-1m.csv.zip"
MALICIOUS_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://phishunt.io/feed.txt"
]


DEFAULT_BATCH = 16
GRAD_ACCUM_STEPS = 2
EPOCHS = 10
LR = 5e-5
MAX_LENGTH = 32
SEED = 42

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

FEED_ARCHIVE_DIR = "./dns_feeds"
MAX_FEED_HISTORY = 5

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dns_peft")

RE_IP_LIKE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_PUNY = re.compile(r"xn--", re.I)
RE_LONG_LABEL = re.compile(r"[a-z0-9-]{24,}", re.I)
RE_RANDOM_CHARS = re.compile(r"[a-z]{4,}\d{3,}|[0-9]{4,}[a-z]{4,}", re.I)
RE_NON_ASCII = re.compile(r"[^\x00-\x7F]")
RE_MIXED_CASE = re.compile(r"(?=.*[a-z])(?=.*[A-Z])")

def regex_heuristics(domain: str):
    matches = []
    if RE_IP_LIKE.search(domain): matches.append("ip_like")
    if RE_PUNY.search(domain): matches.append("punycode")
    if RE_LONG_LABEL.search(domain): matches.append("long_label")
    if RE_RANDOM_CHARS.search(domain): matches.append("random_alphanumeric")
    if RE_NON_ASCII.search(domain): matches.append("non_ascii")
    if RE_MIXED_CASE.search(domain): matches.append("mixed_case")
    return matches


def get_whois_age(domain: str, fallback=None):
    """Return age in days or None on error."""
    try:
        w = whois.whois(domain)
        cdate = w.creation_date
        if isinstance(cdate, list):
            cdate = cdate[0] if cdate else None
        if not cdate:
            return fallback
        return (datetime.utcnow() - cdate).days
    except Exception:
        return fallback

def passive_dns_info(domain: str):
    """Return some lightweight PDNS info (num ips, ns_count). Exceptions return zeros."""
    try:
        ips = set()
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=3.0)
            ips.update([rdata.address for rdata in answers])
        except Exception:
            pass
        ns_count = 0
        try:
            ns = dns.resolver.resolve(domain, "NS", lifetime=3.0)
            ns_count = len(ns)
        except Exception:
            ns_count = 0
        return {"num_ips": len(ips), "ns_count": ns_count, "ips": sorted(list(ips))}
    except Exception:
        return {"num_ips": 0, "ns_count": 0, "ips": []}
    
def fetch_tranco(limit=100000):
    """Return list of top domains from Tranco (may be slow)."""
    try:
        df = pd.read_csv(BENIGN_URL, compression="zip", header=None, names=["rank", "domain"])
        return df["domain"].head(limit).astype(str).tolist()
    except Exception as e:
        logger.warning("Tranco fetch failed: %s — falling back to synthetic benigns", e)
        words = ["home","login","account","cdn","service","api","static","docs","secure","portal"]
        tlds = ["com","net","org","io","dev"]
        out = []
        for _ in range(min(limit, 20000)):
            out.append(random.choice(words) + random.choice(words) + str(random.randint(0,99)) + "." + random.choice(tlds))
        return out


def fetch_threat_feeds():
    """Fetch malicious hostnames from simple feeds (deduplicated, skip IPs)."""
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

                    try:
                        ipaddress.ip_address(host)
                        continue  
                    except ValueError:
                        pass  

                    malicious.add(host)

                except Exception:
                    continue

        except Exception as e:
            logger.debug("feed fetch error %s: %s", feed, e)
            continue

    return list(malicious)


def make_dataset(benign, malicious, max_examples=None):
    """Create a HuggingFace Dataset with 'text' and 'label' fields."""
    max_example = len(benign) if len(benign) > len(malicious) else len(malicious)
    max_example = max_examples if max_examples != None and max_examples < max_example else max_example
    benign = benign[:max_example-1]
    malicious = malicious[:max_example - 1]
    rows = []
    for d in benign:
        rows.append({"text": f"domain: {d}", "label": 0})
    for d in malicious:
        rows.append({"text": f"domain: {d}", "label": 1})
    random.shuffle(rows)
    df = pd.DataFrame(rows)
    return Dataset.from_pandas(df)

def save_feed_snapshot(benign_list, malicious_list):
    """
    Save benign and malicious domain lists as timestamped CSV files
    and keep only the last MAX_FEED_HISTORY snapshots.
    """
    os.makedirs(FEED_ARCHIVE_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    benign_path = os.path.join(FEED_ARCHIVE_DIR, f"benign_{ts}.csv")
    malicious_path = os.path.join(FEED_ARCHIVE_DIR, f"malicious_{ts}.csv")

    pd.DataFrame(benign_list, columns=["domain"]).to_csv(benign_path, index=False)
    pd.DataFrame(malicious_list, columns=["domain"]).to_csv(malicious_path, index=False)


    all_files = sorted(
        [f for f in os.listdir(FEED_ARCHIVE_DIR) if f.endswith(".csv")],
        key=lambda f: os.path.getmtime(os.path.join(FEED_ARCHIVE_DIR, f)),
        reverse=True,
    )

    for old in all_files[MAX_FEED_HISTORY * 2:]: 
        os.remove(os.path.join(FEED_ARCHIVE_DIR, old))

    print(f"[+] Saved new feed snapshot — benign: {benign_path}, malicious: {malicious_path}")
    
def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    acc = accuracy_score(labels, preds)
    f1 = f1_score(labels, preds, zero_division=0)
    return {"accuracy": acc, "f1": f1}


def init_peft_model(base_model_name=BASE_MODEL, lora_r=8, lora_alpha=16, lora_dropout=0.1, target_modules=None):
    logger.info("Initializing tokenizer and base model: %s", base_model_name)
    if os.path.exists(MERGED_MODEL_DIR) and os.listdir(MERGED_MODEL_DIR):
        print("[*] Loading existing PEFT model for incremental update...")
        tokenizer = AutoTokenizer.from_pretrained(MERGED_MODEL_DIR)
        base_model = AutoModelForSequenceClassification.from_pretrained(MERGED_MODEL_DIR)
    else:
        print("[*] No existing model found, initializing from base DistilBERT...")
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
        base_model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)
    if target_modules is None:
        target_modules = ["q_lin", "v_lin"]
    peft_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=target_modules,
        lora_dropout=lora_dropout,
        bias="none",
        task_type="SEQ_CLS",
    )
    model = get_peft_model(base_model, peft_config)
    model.print_trainable_parameters()
    model.to(DEVICE)
    return tokenizer, model



def save_peft_and_merged(model, tokenizer, model_dir=MODEL_DIR, merged_dir=MERGED_MODEL_DIR):
    """Save adapter (PEFT) and also save a merged version for inference without PEFT."""
    os.makedirs(model_dir, exist_ok=True)
    logger.info("Saving PEFT adapter to %s", model_dir)
    model.save_pretrained(model_dir)
    tokenizer.save_pretrained(model_dir)
    # try:
    if isinstance(model, PeftModel):
        logger.info("Merging LoRA adapters into base model for merged export...")
        merged = model.merge_and_unload()  
        os.makedirs(merged_dir, exist_ok=True)
        merged.save_pretrained(merged_dir)
        tokenizer.save_pretrained(merged_dir)
        logger.info("Merged model exported to %s", merged_dir)
    else:
        logger.info("Model is not PeftModel; skipping merge step.")
    # except Exception as e:
    #     logger.warning("Failed to create merged model: %s", e)

def update_model(
    batch_size=DEFAULT_BATCH,
    grad_accum=GRAD_ACCUM_STEPS,
    epochs=EPOCHS,
    max_examples_per_class=20000
):
    """Main function to fetch feeds and fine-tune (LoRA)."""
    logger.info("Starting update_model() — fetching data...")
    benign = fetch_tranco(limit=max_examples_per_class*2)
    malicious = fetch_threat_feeds()
    
    save_feed_snapshot(benign, malicious)

    if len(malicious) == 0:
        logger.warning("No malicious domains found from feeds; aborting update")
        return None, None

    ds = make_dataset(benign[:max_examples_per_class], malicious[:max_examples_per_class])

    tokenizer, model = init_peft_model()
    def tokenize_fn(batch):
        return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=MAX_LENGTH)
    remove_cols = [c for c in ["text", "__index_level_0__"] if c in ds.column_names]
    tokenized = ds.map(tokenize_fn, batched=True, remove_columns=remove_cols, load_from_cache_file=False)
    tokenized = tokenized.rename_column("label", "labels")
    tokenized.set_format(type="torch")

    split = tokenized.train_test_split(test_size=0.1, seed=SEED)
    train_dataset = split["train"]
    eval_dataset = split["test"]

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    args = TrainingArguments(
        output_dir="./results",
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=epochs,
        eval_strategy="epoch",
        save_strategy="no",
        learning_rate=LR,
        logging_dir="./logs",
        logging_strategy="epoch",
        seed=SEED,
        remove_unused_columns=False
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics
    )

    logger.info("Starting training: epochs=%s batch=%s grad_accum=%s fp16=%s", epochs, batch_size, grad_accum, args.fp16)
    trainer.train()
    logger.info("Training finished — saving models")
    save_peft_and_merged(model, tokenizer)
    return tokenizer, model

def load_model(model_dir=MODEL_DIR, merged_dir=MERGED_MODEL_DIR):
    """Load the model for inference.
    Preferred: load merged model (no PEFT dependency) if exists.
    Fallback: load base model + PeftModel adapter.
    """
    if os.path.isdir(merged_dir):
        logger.info("Loading merged model from %s", merged_dir)
        tokenizer = AutoTokenizer.from_pretrained(merged_dir, use_fast=True)
        model = AutoModelForSequenceClassification.from_pretrained(merged_dir)
        model.to(DEVICE)
        return tokenizer, model


    if os.path.isdir(model_dir):
        logger.info("Loading base model and applying PEFT adapter from %s", model_dir)
        tokenizer = AutoTokenizer.from_pretrained(model_dir, use_fast=True)
        base = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)
        model = PeftModel.from_pretrained(base, model_dir)
        model.to(DEVICE)
        return tokenizer, model

    raise FileNotFoundError("No trained model found in merged_dir or model_dir")


def ai_infer(domain, tokenizer, model):
    text = f"domain: {domain}"
    tokens = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=MAX_LENGTH).to(DEVICE)
    model.eval()
    with torch.no_grad():
        out = model(**tokens)
        logits = out.logits
        probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]
        return float(probs[1])

def dns_action(qname, tokenizer, model,blocklist, ml_threshold=0.9):
    
    if qname in blocklist:
        return {"domain" : qname, "decision" : "BLOCKED", "score" : 1.00, "whois_age" : "null", "pdns" : "null", "reason" : "blocklist:domain"}
    q = qname.strip().lower().rstrip(".")
    if qname in blocklist:
        return {"domain" : qname, "decision" : "BLOCKED", "score" : 1.00, "whois_age" : "null", "pdns" : "null", "reason" : "blocklist:domain"}
    
    heur = regex_heuristics(q)
    if heur:
        return {"domain": q, "decision": "BLOCKED", "score": 0.95, "whois_age": "null", "pdns": "null", "reason": f"regex:{','.join(heur)}"}

    # whois_age = get_whois_age(q)
    # pdns = passive_dns_info(q)
    
    score = ai_infer(q, tokenizer, model)

    if score >= ml_threshold:
        decision = "BLOCKED"; reason = "ai_malicious"
    elif score >= (ml_threshold * 0.6):
        decision = "ALLOWED"; reason = "ai_suspicious"
    else:
        decision = "ALLOWED"; reason = "ai_safe"

    return {"domain": q, "decision": decision, "score": score, "whois_age_days": "null", "pdns": "null", "reason": reason}
