# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

from auditwheel.wheel_abi import analyze_wheel_abi, NonPlatformWheel
from auditwheel.policy import WheelPolicies
from pathlib import Path
import sys

file = Path(sys.argv[1])

try:
    winfo = analyze_wheel_abi(WheelPolicies(), file, frozenset(), False)
except NonPlatformWheel as e:
    print(e.message)
    exit(1)

print(winfo.sym_policy.name)
