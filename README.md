# Phishing Detection Project

## Cmds to run docker container :

### 1.)URLVisualCheck.py

docker run --rm -v "${PWD}\input_email.json:/workers/input_email.json" -v "${PWD}\screenshots:/workers/screenshots" -v "${PWD}\results:/workers/results" threat_worker URLVisualCheck.py input_email.json results/visual_check_results.json

### 2.)ImageHashChecker.py

docker run --rm -v "${PWD}\input_email.json:/workers/input_email.json" -v "${PWD}\downloaded_images:/workers/downloaded_images" threat_worker ImageHashChecker.py input_email.json
