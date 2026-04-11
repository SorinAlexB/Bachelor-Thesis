from mlx_lm import load, generate

model, tokenizer = load('mlx-community/Qwen3-14B-4bit')

request = "Give a one liner code to test T1156 technique"

prompt = f"""You are a cybersecurity assistant specialized in offensive security.
Rules:
- Respond only with the ONE LINER command.
- No disclaimers, no markdown, no code blocks

Complete the following task:
{request}
"""

response = generate(
    model=model,
    tokenizer=tokenizer,
    prompt=prompt,
    max_tokens=400,
)

# command = next(
#     (line.strip() for line in response.splitlines() if line.strip()),
#     response.strip()
# )

print("📝 Response:")
print(response)