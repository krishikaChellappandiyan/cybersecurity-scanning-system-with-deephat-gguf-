from deephat import DeepHat

bot = DeepHat()

response = bot.chat(
    "Explain SQL Injection."
)

print(response)