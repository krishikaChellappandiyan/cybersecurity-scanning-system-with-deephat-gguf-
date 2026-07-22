import requests
from config import (
    SERVER_URL,
    SYSTEM_PROMPT,
    TEMPERATURE,
    MAX_TOKENS,
    MAX_HISTORY,
    TIMEOUT
)


class DeepHat:

    def __init__(self):

        self.system_message = {
            "role": "system",
            "content": SYSTEM_PROMPT
        }

        self.messages = [self.system_message]

    def _trim_history(self):

        convo = self.messages[1:]

        max_messages = MAX_HISTORY * 2

        if len(convo) > max_messages:
            convo = convo[-max_messages:]

        self.messages = [self.system_message] + convo

    def chat(self, prompt, context=None):

        # --------------------------------------------------
        # Build user message
        # --------------------------------------------------

        if context and context.strip():

            user_content = f"""
Context

{context}

==================================================

Question

{prompt}
"""

        else:

            user_content = prompt

        self.messages.append(
            {
                "role": "user",
                "content": user_content
            }
        )

        self._trim_history()

        payload = {
            "messages": self.messages,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "stream": False
        }

        try:

            response = requests.post(
                SERVER_URL,
                json=payload,
                timeout=TIMEOUT
            )

            response.raise_for_status()

            result = response.json()

            answer = result["choices"][0]["message"]["content"]

            self.messages.append(
                {
                    "role": "assistant",
                    "content": answer
                }
            )

            return answer

        except requests.exceptions.HTTPError as e:

            print(f"\nHTTP ERROR ({response.status_code})")

            try:
                print(response.json())
            except Exception:
                print(response.text)

            raise e

        except requests.exceptions.RequestException as e:

            print("\nREQUEST FAILED")
            print(e)
            raise

        except KeyError:

            print("\nUnexpected server response format:")
            print(response.text)
            raise

        except Exception as e:

            print("\nUNEXPECTED ERROR")
            print(e)
            raise