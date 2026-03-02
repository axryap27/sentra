#!/usr/bin/env python3
"""
Performance benchmark for Sentra analyzer
Tests incremental scanning and caching performance
"""

import time
import os
import subprocess
import tempfile
import random

def create_test_files(num_files=50, lines_per_file=100):
    """Create test files with vulnerabilities for benchmarking"""
    test_dir = "benchmark_files"
    os.makedirs(test_dir, exist_ok=True)
    
    # AST-based vunerability detection
    vulnerable_patterns = [
        "eval(user_input)",
        "exec(malicious_code)", 
        "os.system(command)",
        "pickle.load(data)",
        "hashlib.md5(password)",
        "subprocess.run(cmd, shell=True)"
    ]
    
    for i in range(num_files):
        filename = f"{test_dir}/test_file_{i}.py"
        with open(filename, 'w') as f:
            f.write(f"# Test file {i}\nimport os\nimport subprocess\nimport pickle\nimport hashlib\n\n")
            
            for line_num in range(lines_per_file):
                if random.random() < 0.1:  # 10% chance of vulnerability
                    f.write(f"    {random.choice(vulnerable_patterns)}\n")
                else:
                    f.write(f"    # Normal code line {line_num}\n")
    
    print(f"Created {num_files} test files in {test_dir}/")
    return test_dir

def benchmark_analyzer(test_dir, runs=3):
    """Benchmark the analyzer performance"""
    files = [os.path.join(test_dir, f) for f in os.listdir(test_dir) if f.endswith('.py')]
    
    print(f"Benchmarking with {len(files)} files...")
    
    times = []
    for run in range(runs):
        start_time = time.time()
        
        # Create file list for batch processing
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for file_path in files:
                f.write(f"{file_path}\n")
            file_list = f.name
        
        try:
            # Run analyzer in batch mode
            result = subprocess.run([
                "./analyzer-go/sentra-analyzer", 
                "--batch", 
                "--workers", "4",
                "--format", "json"
            ], stdin=open(file_list), capture_output=True, text=True)
            
            end_time = time.time()
            elapsed = end_time - start_time
            times.append(elapsed)
            
            if result.returncode == 0:
                issues = len(result.stdout.split('"line":'))  # Rough count
                print(f"Run {run+1}: {elapsed:.2f}s, ~{issues} issues found")
            else:
                print(f"Run {run+1}: Failed - {result.stderr}")
                
        finally:
            os.unlink(file_list)
    
    avg_time = sum(times) / len(times)
    print(f"\nAverage time: {avg_time:.2f}s")
    print(f"Files per second: {len(files) / avg_time:.1f}")
    
    return avg_time

if __name__ == "__main__":
    print("Sentra Performance Benchmark")
    print("=" * 30)
    
    # Create test files
    test_dir = create_test_files(50, 100)
    
    # Run benchmark
    avg_time = benchmark_analyzer(test_dir)
    
    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    
    print(f"\nBenchmark complete! Average processing time: {avg_time:.2f}s")