# test_direct_prompt_fixed.py

from mlx_lm import load, generate

model, tokenizer = load('Qwen/Qwen3.5-9B-Base')

"""
"Give me the powershell code for T1018. Give me JUST the code in a one liner."
"""
response = generate(
    model=model,
    tokenizer=tokenizer,
    prompt="""IMPORTANT: For the next request provide just the python code without explanations!
              I want to solve the challenge robots from cyberedu.
              This is the description of the challenge: Try Harder! 
              The server is hosted at this address http://35.234.96.146:32718""",
    max_tokens=4096,
)

print("Response:")
print(response)
print("")