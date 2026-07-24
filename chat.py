import json

from deephat import DeepHat
from context.spider_context_builder import SpiderContextBuilder
from processing.spider_extractor import SpiderExtractor
from pipeline.crawler import HellhoundCrawler


bot = DeepHat()
crawler = HellhoundCrawler()
extractor = SpiderExtractor()
spider_context_builder = SpiderContextBuilder()

print("=" * 60)
print(" DeepHat Cybersecurity Assistant")
print("=" * 60)

while True:

    print("\nChoose Mode")
    print("1. Normal Chat")
    print("2. Website Security Analysis")
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
    # WEBSITE SECURITY ANALYSIS
    # ==========================================================

    elif choice == "2":

        target = input("\nTarget URL : ").strip()

        try:
            print("\nRunning Hellhound Spider...\n")

            json_path = crawler.crawl(target)

            print(f"\nSpider report generated:\n{json_path}")

            with open(json_path, "r", encoding="utf-8") as f:
                spider_json = json.load(f)

        except Exception as e:
            print(f"\nCrawler failed: {e}")
            continue

        # ------------------------------------------------------
        # Extract important security evidence
        # ------------------------------------------------------

        extracted_json = extractor.extract(spider_json)

        # ------------------------------------------------------
        # Build LLM-friendly context
        # ------------------------------------------------------

        spider_summary = spider_context_builder.build(extracted_json)

        print("\nSpider scan completed successfully.")
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
    # DEEPHAT
    # ==========================================================

    print("\nDeepHat is thinking...\n")

    try:
        answer = bot.chat(prompt=prompt)

        print("\n================ DEEPHAT =================\n")
        print(answer)
        print("\n==========================================\n")

    except Exception as e:
        print(f"\nDeepHat Error: {e}")