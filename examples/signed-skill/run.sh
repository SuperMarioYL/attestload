#!/bin/sh
# A trivial support file so the example Skill is more than a single document.
# AttestLoad attests every file in the directory, so this file's bytes are part
# of the signed digest — change one character and verify will refuse to load.
echo "hello from the signed example skill"
