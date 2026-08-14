import re
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

    def reset(self):
        """
        Clear conversation history back to just the system message.

        Each Website Security Analysis scan is a self-contained request —
        DeepHat doesn't need (and shouldn't want) memory of a previous,
        unrelated target's scan. Without this, self.messages accumulates
        every prior scan's full spider-context prompt and JSON reply
        (capped at MAX_HISTORY*2 messages, not by token count), so context
        size — and therefore local inference time — grows with every scan
        run in the same session, eventually exceeding even a generous
        TIMEOUT on local hardware. Call this before each new scan.
        """
        self.messages = [self.system_message]

    def _trim_history(self):

        convo = self.messages[1:]

        max_messages = MAX_HISTORY * 2

        if len(convo) > max_messages:
            convo = convo[-max_messages:]

        self.messages = [self.system_message] + convo

    def _clean_response(self, text: str) -> str:
        """
        Remove Markdown code fences if the model returns:

        ```json
        {...}
        ```

        Returns the cleaned JSON string.
        """

        text = text.strip()

        text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE)
        text = re.sub(r"```$", "", text)

        return text.strip()

    def chat(self, prompt):

        self.messages.append(
            {
                "role": "user",
                "content": prompt
            }
        )

        self._trim_history()

        payload = {
            "messages": self.messages,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "stream": False,
            # The system prompt forbids markdown/explanations in the
            # output entirely, so any of these appearing means the model
            # has already finished the JSON and started drifting — cut
            # generation there instead of burning the rest of MAX_TOKENS
            # on commentary (which has also been observed degenerating
            # into repeated filler paragraphs until the token limit).
            "stop": ["\n##", "\n```", "\n\n##", "## Explanation"]
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

            answer = self._clean_response(answer)

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

            raise

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