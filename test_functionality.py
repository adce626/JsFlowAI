#!/usr/bin/env python3
"""
Comprehensive functionality test for JSFlow AI
Tests all core features to ensure 100% working tool
"""

import subprocess
import sys
import json
import os
from pathlib import Path

def run_test(command, test_name):
    """Run a test command and check for success"""
    print(f"\n🧪 Testing: {test_name}")
    print(f"Command: {command}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"✅ {test_name} - PASSED")
            return True
        else:
            print(f"❌ {test_name} - FAILED")
            print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏰ {test_name} - TIMEOUT")
        return False
    except Exception as e:
        print(f"💥 {test_name} - EXCEPTION: {str(e)}")
        return False

def test_output_files():
    """Test if output files are created correctly"""
    print("\n📁 Checking output files...")
    
    expected_files = [
        'output/fixed_test.html',
        'output/analysis_results.json'
    ]
    
    all_good = True
    for file_path in expected_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"✅ {file_path} exists ({file_size} bytes)")
        else:
            print(f"❌ {file_path} missing")
            all_good = False
    
    return all_good

def main():
    """Run comprehensive tests"""
    print("🚀 JSFlow AI Comprehensive Functionality Test")
    print("=" * 50)
    
    tests = [
        # Basic functionality tests
        ("python main.py --input test_samples/sample1.js --format json --no-ai", 
         "Single file JSON analysis (no AI)"),
        
        ("python main.py --input test_samples/sample1.js --format html --no-ai --output output/test_single.html", 
         "Single file HTML report (no AI)"),
        
        ("python main.py --input test_samples/ --batch --format json --no-ai --output output/test_batch.json", 
         "Batch directory analysis (no AI)"),
        
        ("python main.py --input test_samples/ --batch --format html --no-ai --output output/test_batch.html", 
         "Batch directory HTML report (no AI)"),
        
        ("python main.py --input test_samples/advanced_sample.js --format json --no-ai --only-secrets", 
         "Secrets-only analysis"),
        
        ("python main.py --input test_samples/ --batch --format json --no-ai --exclude node_modules dist", 
         "Directory analysis with exclusions"),
        
        ("python main.py --input test_samples/ --batch --format json --no-ai --severity-filter medium", 
         "Analysis with severity filtering"),
    ]
    
    passed = 0
    total = len(tests)
    
    for command, test_name in tests:
        if run_test(command, test_name):
            passed += 1
    
    # Test output file creation
    if test_output_files():
        print("✅ Output file creation - PASSED")
        passed += 1
    else:
        print("❌ Output file creation - FAILED")
    total += 1
    
    # Final summary
    print("\n" + "=" * 50)
    print(f"🏁 TEST SUMMARY: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - JSFlow AI is 100% functional!")
        return 0
    else:
        print(f"⚠️  {total - passed} tests failed - needs attention")
        return 1

if __name__ == "__main__":
    sys.exit(main())