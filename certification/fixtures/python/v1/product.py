#!/usr/bin/env python3
import sys
print('python-product-v1' if '--health' not in sys.argv else 'healthy-v1')
raise SystemExit(0)