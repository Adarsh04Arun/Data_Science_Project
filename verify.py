import sys
import os

# 1. Check for GPU-Accelerated Pandas (cuDF)
try:
    import cudf
    import cudf.pandas
    cudf.pandas.install()
    print("✅ SUCCESS: cuDF (GPU Pandas) is correctly installed.")
except ImportError:
    print("❌ FAILED: cuDF not found. Install with: pip install --extra-index-url=https://pypi.nvidia.com cudf-cu12")

# 2. Check for GPU-Accelerated XGBoost
try:
    import xgboost as xgb
    import numpy as np
    
    # Simple test: Can we build a DMatrix on the GPU?
    data = np.random.rand(10, 10)
    label = np.random.randint(2, size=10)
    
    # XGBoost 3.0+ syntax for GPU verification
    dmat = xgb.DMatrix(data, label=label)
    params = {'tree_method': 'hist', 'device': 'cuda'}
    bst = xgb.train(params, dmat, num_boost_round=1)
    
    print(f"✅ SUCCESS: XGBoost is using GPU device: {params['device']}")
except Exception as e:
    print(f"❌ FAILED: XGBoost GPU test failed. Error: {e}")

# 3. Check System Visibility via Command Line
print("-" * 30)
os.system("nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv")
