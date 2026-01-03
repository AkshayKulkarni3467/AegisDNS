import torch
import os
import sys

# Add the directory to path so we can import dns_model
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import after path is set
from dns_model import DomainFeatureExtractor, DNSSecurityModel

MODEL_DIR = "./dns_model"
BASE_MODEL_PATH = os.path.join(MODEL_DIR, "base_model.pt")
MERGED_MODEL_PATH = os.path.join(MODEL_DIR, "merged_model.pt")
LORA_ADAPTER_PATH = os.path.join(MODEL_DIR, "lora_adapter.pt")

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

def convert_model(old_path, new_path):
    """Convert old model format to new format without pickled objects"""
    print(f"\nConverting: {old_path}")
    print(f"Output to: {new_path}")
    
    try:
        # Load with weights_only=False (old way that allows pickle)
        # This works because we're running from a script where dns_model classes are available
        checkpoint = torch.load(old_path, map_location=DEVICE, weights_only=False)
        
        print("  ✓ Loaded old checkpoint")
        
        # Create new checkpoint without pickled objects
        new_checkpoint = {
            'model_state_dict': checkpoint['model_state_dict'],
            'metrics': checkpoint.get('metrics', {})
            # Removed 'feature_extractor' - we'll recreate it instead
        }
        
        print("  ✓ Created new checkpoint (tensors only)")
        
        # Save with new format (only tensors, no Python objects)
        torch.save(new_checkpoint, new_path)
        
        print(f"  ✓ Saved to {new_path}")
        
        # Verify it can be loaded with weights_only=True
        test_load = torch.load(new_path, map_location=DEVICE, weights_only=True)
        print("  ✓ Verified: Can load with weights_only=True")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def main():
    print("=" * 70)
    print("DNS MODEL CONVERTER - Removing Pickled Objects")
    print("=" * 70)
    
    converted_count = 0
    
    # Convert base model
    if os.path.exists(BASE_MODEL_PATH):
        backup = BASE_MODEL_PATH + ".backup"
        print(f"\n[1/3] Base Model")
        print(f"  Creating backup: {backup}")
        
        # Backup original
        if not os.path.exists(backup):
            os.rename(BASE_MODEL_PATH, backup)
        else:
            print(f"  (Backup already exists, using it)")
            if os.path.exists(BASE_MODEL_PATH):
                os.remove(BASE_MODEL_PATH)
        
        if convert_model(backup, BASE_MODEL_PATH):
            converted_count += 1
    else:
        print(f"\n[1/3] Base Model: Not found (skipping)")
    
    # Convert merged model
    if os.path.exists(MERGED_MODEL_PATH):
        backup = MERGED_MODEL_PATH + ".backup"
        print(f"\n[2/3] Merged Model")
        print(f"  Creating backup: {backup}")
        
        # Backup original
        if not os.path.exists(backup):
            os.rename(MERGED_MODEL_PATH, backup)
        else:
            print(f"  (Backup already exists, using it)")
            if os.path.exists(MERGED_MODEL_PATH):
                os.remove(MERGED_MODEL_PATH)
        
        if convert_model(backup, MERGED_MODEL_PATH):
            converted_count += 1
    else:
        print(f"\n[2/3] Merged Model: Not found (skipping)")
    
    # Convert LoRA adapter
    if os.path.exists(LORA_ADAPTER_PATH):
        backup = LORA_ADAPTER_PATH + ".backup"
        print(f"\n[3/3] LoRA Adapter")
        print(f"  Creating backup: {backup}")
        
        # Backup original
        if not os.path.exists(backup):
            os.rename(LORA_ADAPTER_PATH, backup)
        else:
            print(f"  (Backup already exists, using it)")
            if os.path.exists(LORA_ADAPTER_PATH):
                os.remove(LORA_ADAPTER_PATH)
        
        if convert_model(backup, LORA_ADAPTER_PATH):
            converted_count += 1
    else:
        print(f"\n[3/3] LoRA Adapter: Not found (skipping)")
    
    print("\n" + "=" * 70)
    print(f"CONVERSION COMPLETE - {converted_count} model(s) converted")
    print("=" * 70)
    
    if converted_count > 0:
        print("\n✓ You can now run: python dns_dashboard.py")
        print("\nNote: Original models backed up with .backup extension")
        print("      You can delete backups once you've verified everything works")
    else:
        print("\n⚠ No models found to convert")
        print("   You may need to train a base model first:")
        print("   python dns_model.py train_base")

if __name__ == "__main__":
    main()