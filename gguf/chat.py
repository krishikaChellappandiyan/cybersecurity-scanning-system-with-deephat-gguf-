import json

from deephat import DeepHat
from context.spider_context_builder import SpiderContextBuilder
from processing.spider_extractor import SpiderExtractor

bot = DeepHat()
spider_context_builder = SpiderContextBuilder()
extractor = SpiderExtractor()

print("=" * 60)
print(" DeepHat Cybersecurity Assistant")
print("=" * 60)

while True:

    print("\nChoose Mode")
    print("1. Normal Chat")
    print("2. Spider JSON Analysis")
    print("3. Exit")

    choice = input("\nChoice : ").strip()

    if choice == "3":
        break

    # ==========================================================
    # NORMAL CHAT
    # ==========================================================

    if choice == "1":

        prompt = input("\nYou : ")

        if prompt.lower() in ["quit", "exit"]:
            break

    # ==========================================================
    # SPIDER JSON ANALYSIS
    # ==========================================================

    elif choice == "2":

        json_file = input("\nSpider JSON file : ").strip().strip('"')

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                spider_json = json.load(f)

        except Exception as e:
            print(f"\nFailed to load JSON : {e}")
            continue

        # ----------------------------------------------
        # Extract important crawler evidence
        # ----------------------------------------------

        extracted_json = extractor.extract(spider_json)

        # ----------------------------------------------
        # Convert JSON into LLM-friendly summary
        # ----------------------------------------------

        spider_summary = spider_context_builder.build(extracted_json)

        print("\nSpider JSON loaded successfully.")
        print("Using extracted security context for analysis.")

        print("\n================ SPIDER SUMMARY ================\n")
        print(spider_summary)
        print("\n================================================\n")

        task = input("\nAnalysis Prompt : ")

        prompt = f"""
==========================
Spider Scan Summary
==========================

{spider_summary}

==========================
Task
==========================

{task}
"""

    else:
        print("Invalid Choice")
        continue

    # ==========================================================
    # DEEPHAT (NO RAG)
    # ==========================================================

    answer = bot.chat(prompt=prompt)

    print("\nDeepHat:\n")
    print(answer)