# Security Review Agent

A Claude-powered agent that reviews vulnerable code packages, identifies security issues, explains impact, and produces minimal patches.

## How it works

1. Identify - vulnerability type, affected file and line
2. Impact - realistic exploit scenario and business impact
3. Fix - minimal patch targeting the root cause only

## Running locally

pip install -r requirements.txt
set ANTHROPIC_API_KEY=sk-ant-...
python solution.py

## Docker

docker build -t security-review .
docker run --rm -e ANTHROPIC_API_KEY=your_key -v path/to/test_inputs.json:/workspace/test_inputs.json security-review

See decisions.md for architectural choices.
