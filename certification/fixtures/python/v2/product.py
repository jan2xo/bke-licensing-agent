#!/usr/bin/env python3
import sys
print('python-product-v2' if '--health' not in sys.argv else 'healthy-v2')
raise SystemExit(0)