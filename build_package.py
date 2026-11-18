"""
SecureShare Deployment Package Builder
Creates a ready-to-deploy zip archive containing lambda_function.py
and required dependencies (Werkzeug, MarkupSafe).
"""

import os
import shutil
import zipfile
import sys
import importlib

def copy_module(mod_name, dest_dir):
    try:
        mod = importlib.import_module(mod_name)
        if hasattr(mod, "__file__") and mod.__file__:
            pkg_dir = os.path.dirname(mod.__file__)
            target = os.path.join(dest_dir, mod_name)
            if os.path.isdir(pkg_dir):
                shutil.copytree(pkg_dir, target, dirs_exist_ok=True)
            else:
                shutil.copy(mod.__file__, dest_dir)
            print(f"Copied {mod_name} from {pkg_dir}")
    except Exception as e:
        print(f"Warning: Could not copy {mod_name}: {e}")

def build():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(root_dir, "dist")
    package_dir = os.path.join(dist_dir, "package")
    zip_path = os.path.join(dist_dir, "secureshare-lambda.zip")

    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    os.makedirs(package_dir, exist_ok=True)

    print("1. Bundling dependencies (werkzeug, markupsafe)...")
    copy_module("werkzeug", package_dir)
    copy_module("markupsafe", package_dir)

    print("2. Copying lambda_function.py...")
    shutil.copy(os.path.join(root_dir, "lambda_function.py"), package_dir)

    print("3. Creating zip archive...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, package_dir)
                zf.write(file_path, arcname)

    print(f"\nSUCCESS: Created Lambda deployment bundle at:\n  {zip_path}")
    print(f"Size: {os.path.getsize(zip_path) / 1024:.2f} KB")

if __name__ == "__main__":
    build()
