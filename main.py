from openai import OpenAI
from dotenv import load_dotenv
import os
import json
import mysql.connector

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url="https://openrouter.ai/api/v1"
)

db = mysql.connector.connect(
    host=os.getenv("MYSQL_HOST"),
    user=os.getenv("MYSQL_USER"),
    password=os.getenv("MY_SQL_PASSWORD"),
    database=os.getenv("DATABASE")
)

conversation_memory = []


def detect_red_flags(message):
    red_flags = []

    message = message.lower()

    if "digital arrest" in message:
        red_flags.append("Digital arrest threat")

    if "police" in message or "cbi" in message or "cyber crime" in message:
        red_flags.append("Authority impersonation")

    if "transfer" in message or "pay" in message or "payment" in message:
        red_flags.append("Payment demand")

    if "otp" in message or "verification code" in message:
        red_flags.append("OTP / verification code request")

    if "bank" in message or "your bank" in message:
        red_flags.append("Bank impersonation")

    if "http://" in message or "https://" in message:
        red_flags.append("Suspicious URL detected")    

    if (
        "anydesk" in message
        or "teamviewer" in message
        or "remote access" in message
        or "screen sharing" in message
    ):
        red_flags.append("Remote access / screen sharing request")

    if "arrest" in message or "jail" in message:
        red_flags.append("Threat of legal action")

    if "immediately" in message or "urgent" in message:
        red_flags.append("Urgency / pressure")

    if (
        "bank account" in message
        or "account will be blocked" in message
        or "account will be frozen" in message
        or "account freeze" in message
    ):
        red_flags.append("Bank / account threat")

    if (
        "kyc" in message
        or "kyc update" in message
        or "kyc verification" in message
    ):
        red_flags.append("KYC-related request")

    if (
        "money laundering" in message
        or "illegal transaction" in message
        or "suspicious transaction" in message
    ):
        red_flags.append("Financial crime allegation")

    if (
        "password" in message
        or "pin" in message
        or "cvv" in message
        or "aadhaar" in message
        or "pan card" in message
        or "bank details" in message
    ):
        red_flags.append("Sensitive information request")

    if (
        "video call" in message
        or "stay on the call" in message
        or "do not disconnect" in message
    ):
        red_flags.append("Isolation / video call pressure")

    return red_flags


def calculate_risk_score(red_flags):
    score = 0

    for flag in red_flags:

        if flag == "Digital arrest threat":
            score += 30

        elif flag == "Authority impersonation":
            score += 25

        elif flag == "Payment demand":
            score += 20

        elif flag == "Threat of legal action":
            score += 15

        elif flag == "Urgency / pressure":
            score += 10

        elif flag == "OTP / verification code request":
            score += 20

        elif flag == "Remote access / screen sharing request":
            score += 20

        elif flag == "Bank / account threat":
            score += 15

        elif flag == "Bank impersonation":
            score += 25

        elif flag == "Suspicious URL detected":
            score += 20

        elif flag == "KYC-related request":
            score += 10

        elif flag == "Financial crime allegation":
            score += 15

        elif flag == "Sensitive information request":
            score += 15

        elif flag == "Isolation / video call pressure":
            score += 10

    score = min(score, 100)

    return score


def get_risk_level(score):

    if score <= 30:
        return "LOW"

    elif score <= 60:
        return "MEDIUM"

    elif score <= 80:
        return "HIGH"

    else:
        return "CRITICAL"


def detect_scam_type(red_flags):

    if "Digital arrest threat" in red_flags:
        return "Digital Arrest Scam"

    elif "Authority impersonation" in red_flags:
        return "Authority Impersonation Scam"

    elif "Payment demand" in red_flags:
        return "Payment Scam"

    elif "Threat of legal action" in red_flags:
        return "Legal Threat Scam"

    else:
        return "Unknown / Suspicious Scam"


def generate_safety_recommendations(risk_level, scam_type):

    recommendations = []

    if risk_level == "CRITICAL":
        recommendations.append("Do not transfer any money.")
        recommendations.append(
            "Do not share OTP, PIN, password, or sensitive documents."
        )
        recommendations.append("End the suspicious call or conversation.")
        recommendations.append("Do not install remote-access software.")
        recommendations.append(
            "Verify the person's identity using an official source."
        )

    elif risk_level == "HIGH":
        recommendations.append(
            "Do not make any payment until the claim is independently verified."
        )
        recommendations.append("Do not share OTP or other sensitive information.")
        recommendations.append(
            "Verify the sender's identity through an official channel."
        )

    elif risk_level == "MEDIUM":
        recommendations.append("Be cautious before responding.")
        recommendations.append("Verify the sender and their claims.")
        recommendations.append("Do not share sensitive information.")

    else:
        recommendations.append("No immediate high-risk indicator detected.")
        recommendations.append(
            "Still verify unexpected requests before taking action."
        )

    return recommendations


def verify_authority(authority):

    official_authority = [
        "police",
        "cbi",
        "cyber crime",
        "cybercrime",
        "government",
    ]

    authority = authority.lower()

    if authority in official_authority:
        return {
            "authority": authority,
            "verified": False,
            "message": "Authority claim requires independent verification through an official channel."
        }

    return {
        "authority": authority,
        "verified": False,
        "message": "Unknown authority. Verify independently before trusting the request."
    }


def analyze_payment_request(message):
    payment_keywords = [
        "pay",
        "payment",
        "transfer",
        "send money",
        "upi",
        "bank transfer",
        "deposit",
        "fee",
        "fine",
        "penalty"     
    ]

    message = message.lower()

    detected_keywords = []

    for keyword in payment_keywords:
        if keyword in message:
            detected_keywords.append(keyword)

    if detected_keywords:
        return {
            "payment_request_detected": True,
            "detected_keywords": detected_keywords,
            "risk": "Suspicious payment request",
            "message": "Do not transfer money until the request and sender are independently verified."
        }   

    return {
        "payment_request_detected": False,
        "detected_keywords": [],
        "risk": "No payment request detected",
        "message": "No direct payment request was identified in the message."
    }  


def analyze_url(url):
    url = url.lower().strip()
    suspicious_indicator = []

    if url.startswith("http://"):
        suspicious_indicator.append("Unencrypted HTTP connection")

    if "@" in url:
        suspicious_indicator.append("Misleading URL structure")    

    if "xn--" in url:
        suspicious_indicator.append("Possible punycode / homograph domain")

    suspicious_words = [
        "verify",
        "kyc",
        "login",
        "account",
        "bank",
        "refund",
        "payment",
        "update",
        "secure",
        "confirm"
    ]        

    for word in suspicious_words:
        if word in url:
            suspicious_indicator.append(
                f"Suspicious keyword: {word}"
            )

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".shop",
        ".online",
        ".tk",
        ".ml",
        ".ga",
        ".cf"
    ]

    for tld in suspicious_tlds:
        if tld in url:
            suspicious_indicator.append(
                f"Suspicious domain extension: {tld}"
            )

    if suspicious_indicator:
        return {
            "url": url,
            "suspicious": True,
            "indicators": suspicious_indicator,
            "message": "The URL contains suspicious indicators. Verify the website independently before opening or entering sensitive information."
        }
    return {
        "url": url,
        "suspicious": False,
        "indicators": [],
        "message": "No obvious suspicious URL indicators were detected."
    }
        
def check_threat_intelligence(indicator):
    indicator = indicator.lower().strip()

    known_threats = {
        "secure-bank-verify.xyz": {
            "threat_level": "HIGH",
            "category": "Phishing",
            "reason": "Known test indicator for a suspicious banking/KYC phishing domain."
        },
        "192.0.2.10": {
            "threat_level": "MEDIUM",
            "category": "Suspicious IP",
            "reason": "Known test indicator used for threat-intelligence testing."
        }
        
    }

    if indicator in known_threats:
        threat = known_threats[indicator]

        return {
            "indicator": indicator,
            "known_threat": True,
            "threat_level": threat["threat_level"],
            "category": threat["category"],
            "reason": threat["reason"],
            "message": "Threat intelligence indicates that this indicator requires caution."
        }

    return {
        "indicator":indicator,
        "known_threat": False,
        "threat_level": "UNKNOWN",
        "category": "No known threat in local database",
        "reason": "The indicator was not found in the current local threat-intelligence dataset.",
        "message": "No known threat was found. This does not prove that the indicator is safe."
    }
            

tools = [
    {
        "type": "function",
        "function": {
            "name": "verify_authority",
            "description": "Checks whether a claimed authority is a known authority and indicates that independent verification is required.",
            "parameters": {
                "type": "object",
                "properties": {
                    "authority": {
                        "type": "string",
                        "description": "The authority claimed by the sender, such as police or CBI."
                    }
                },
                "required": ["authority"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_payment_request",
            "description": "Analyzes a message for suspicious payment or money transfer requests.",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message that should be checked for payment-related requests."
                    }
                },
                "required": ["message"]
            }
        }
    },

        {
        "type": "function",
        "function": {
            "name": "analyze_url",
            "description": "Analyzes a URL for suspicious indicator such as HTTP, suspicious keywords, punycode, or suspicious domain extensions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL that should be analyzed for suspicious indicators."
                    }
                },
                "required": ["url"]
            }
        }
    },

        {
        "type": "function",
        "function": {
            "name": "check_threat_intelligence",
            "description": "Checks an indicator such as a domain, IP address, or URL against the available threat intelligence data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The domain, IP address, or URL that should be checked."
                    }
                },
                "required": ["indicator"]
            }
        }
    },
]

def get_selected_tools(tool_calls):
    selected_tools = []

    for tool_call in tool_calls:
        tool_name = tool_call.function.name

        if tool_name not in selected_tools:
            selected_tools.append(tool_name)

    return selected_tools        


def get_required_tools(message):
    required_tools = []

    message_lower = message.lower()

    
    authority_keywords = [
        "police",
        "cbi",
        "cyber crime",
        "government",
        "court",
        "customs",
        "income tax",
        "rbi",
        "official"
    ]

    if any(keyword in message_lower for keyword in authority_keywords):
        required_tools.append("verify_authority")

    
    payment_keywords = [
        "pay",
        "payment",
        "transfer",
        "send money",
        "upi",
        "fee",
        "fine",
        "penalty",
        "deposit"
    ]

    if any(keyword in message_lower for keyword in payment_keywords):
        required_tools.append("analyze_payment_request")

   
    if "http://" in message_lower or "https://" in message_lower:
        required_tools.append("analyze_url")

        
        required_tools.append("check_threat_intelligence")

    return required_tools

def execute_tool_safely(tool_name, arguments):

    max_retries = 1

    for attempt in range(max_retries + 1):

        try:

            if tool_name == "verify_authority":

                return verify_authority(
                    arguments["authority"]
                )

            elif tool_name == "analyze_payment_request":

                return analyze_payment_request(
                    arguments["message"]
                )

            elif tool_name == "analyze_url":

                return analyze_url(
                    arguments["url"]
                )

            elif tool_name == "check_threat_intelligence":

                return check_threat_intelligence(
                    arguments["indicator"]
                )

            else:

                return {
                    "success": False,
                    "error": "Unknown tool",
                    "message": f"Tool '{tool_name}' is not supported.",
                    "recovered": False
                }

        except Exception as e:

            if attempt < max_retries:

                print(
                    f"\nTool '{tool_name}' failed. "
                    f"Retrying..."
                )

                continue

            return {
                "success": False,
                "error": str(e),
                "message": (
                    f"Tool '{tool_name}' failed "
                    f"after retry."
                ),
                "recovered": False
            }

    
def llm_analyze(message,memory_context):

    required_tools = get_required_tools(message)

    system_prompt = f"""
You are Rakshak AI, a cybersecurity scam detection assistant.

Analyze the user's message for possible scam or fraud indicators.

Use the available tools when they are relevant:

- Use verify_authority when the message claims to be from police,
  CBI, cyber crime, government, or another authority.

- Use analyze_payment_request when the message contains or may contain
  a payment, money transfer, UPI, fee, fine, penalty, or financial demand.

- Use analyze_url when the message contains a URL or web link.

- Use check_threat_intelligence when the message contains a suspicious
  domain, IP address, URL, or other technical indicator that should be
  checked against threat intelligence data.

Identify:
1. Scam type
2. Suspicious behavior
3. Why the message may be suspicious
4. Recommended safety action

Previous analysis memory:

{memory_context}

Use this memory only as supporting context. Compare it with the current message when relevant. Do not assume that a new message is a scam simply because a previous message was suspicious.

Be factual and do not claim certainty unless the evidence supports it.
"""

    user_prompt = f"""
Analyze this message:

{message}
"""

    response = client.chat.completions.create(
        model="openai/gpt-4.1-mini",
        messages=[
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        tools=tools,
        tool_choice="auto",
        max_tokens=500
    )

    assistant_message = response.choices[0].message

    if assistant_message.tool_calls:

        selected_tools = get_selected_tools(
            assistant_message.tool_calls
        )

        
        for tool_name in required_tools:
            if tool_name not in selected_tools:
                selected_tools.append(tool_name)

        tool_messages = []
        tool_results = []

        
        for tool_call in assistant_message.tool_calls:

            tool_name = tool_call.function.name

            arguments = json.loads(
                tool_call.function.arguments
            )

            tool_result = execute_tool_safely(
                tool_name,
                arguments
            )


            tool_results.append(
                    {
                        "tool": tool_name,
                        "result": tool_result
                    }
            )
            tool_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(tool_result)
                }
            )

        
        executed_tools = {
            item["tool"]
            for item in tool_results
        }

        
        for tool_name in required_tools:

            if tool_name in executed_tools:
                continue

            if tool_name == "analyze_url":

                import re

                urls = re.findall(
                    r'https?://[^\s]+',
                    message
                )

                for url in urls:

                    tool_result = analyze_url(
                        url
                    )

                    tool_results.append(
                        {
                            "tool": "analyze_url",
                            "result": tool_result
                        }
                    )

                    executed_tools.add(
                        "analyze_url"
                    )

            elif tool_name == "check_threat_intelligence":

                import re

                urls = re.findall(
                    r'https?://[^\s]+',
                    message
                )

                for url in urls:

                    domain = url.split(
                        "//"
                    )[1].split("/")[0]

                    tool_result = check_threat_intelligence(
                        domain
                    )

                    tool_results.append(
                        {
                            "tool": "check_threat_intelligence",
                            "result": tool_result
                        }
                    )

                    executed_tools.add(
                        "check_threat_intelligence"
                    )

        
        response = client.chat.completions.create(
            model="openai/gpt-4.1-mini",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                },
                assistant_message,
                *tool_messages
            ],
            max_tokens=500
        )

        return {
            "analysis": response.choices[0].message.content,
            "tool_results": tool_results,
            "selected_tools": selected_tools
        }

    return {
        "analysis": assistant_message.content,
        "tool_results": [],
        "selected_tools": []
    }

def get_memory():

    if not conversation_memory:
        return []

    return conversation_memory



def retrieve_relevant_memory(current_red_flags, memory):

    if not memory:
        return []

    current_flags = set(current_red_flags)

    relevant_cases = []

    for item in memory:

        previous_flags = set(item["red_flags"])

        shared_flags = current_flags.intersection(
            previous_flags
        )

        if shared_flags:

            relevance_score = len(shared_flags)

            relevant_case = item.copy()

            relevant_case["shared_indicators"] = list(
                shared_flags
            )

            relevant_case["relevance_score"] = relevance_score

            relevant_cases.append(
                relevant_case
            )

    # Most relevant cases first
    relevant_cases.sort(
        key=lambda x: x["relevance_score"],
        reverse=True
    )

    # Keep only top 5 relevant cases
    return relevant_cases[:5]




def load_memory_from_mysql():

    cursor = db.cursor(dictionary=True)

    query = """
        SELECT
            message,
            risk_score,
            risk_level,
            scam_type,
            red_flags,
            selected_tools
        FROM analysis_history
        ORDER BY id ASC
    """

    cursor.execute(query)

    rows = cursor.fetchall()

    cursor.close()

    conversation_memory.clear()

    for row in rows:

        memory_item = {
            "message": row["message"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "scam_type": row["scam_type"],
            "red_flags": json.loads(row["red_flags"]),
            "selected_tools": json.loads(row["selected_tools"])
        }

        conversation_memory.append(memory_item)

    return conversation_memory

def create_memory_summary(memory):

    if not memory:
        return "No previous cases available."

    summary = []

    for index, item in enumerate(memory, start=1):

        summary.append(
            f"Case {index}: "
            f"Risk={item['risk_level']}, "
            f"Score={item['risk_score']}, "
            f"Scam Type={item['scam_type']}, "
            f"Red Flags={', '.join(item['red_flags'])}"
        )

    return "\n".join(summary)



def save_to_memory(message, result):

    memory_item = {
        "message": message,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "scam_type": result["scam_type"],
        "red_flags": result["red_flags"],
        "selected_tools": result["selected_tools"]
    }

    cursor = db.cursor()

    try:

        
        # Check for duplicate message
        

        check_query = """
            SELECT id
            FROM analysis_history
            WHERE message = %s
            LIMIT 1
        """

        cursor.execute(
            check_query,
            (message,)
        )

        existing_record = cursor.fetchone()

        if existing_record:

            # Already exists in MySQL

            if not any(
                item["message"] == message
                for item in conversation_memory
            ):
                conversation_memory.append(memory_item)

            return

        
        # Insert new analysis
        

        insert_query = """
            INSERT INTO analysis_history
            (
                message,
                risk_score,
                risk_level,
                scam_type,
                red_flags,
                selected_tools
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        values = (
            message,
            result["risk_score"],
            result["risk_level"],
            result["scam_type"],
            json.dumps(result["red_flags"]),
            json.dumps(result["selected_tools"])
        )

        cursor.execute(
            insert_query,
            values
        )

        db.commit()

        # Add to memory only after successful DB commit
        conversation_memory.append(memory_item)

    except Exception as e:

        db.rollback()

        print(
            f"\nMemory save failed: {e}"
        )

    finally:

        cursor.close()



def compare_with_memory(
    message,
    current_red_flags,
    memory
):

    if not memory:
        return {
            "similar_case_found": False,
            "message": "No previous cases available.",
            "matches": []
        }

    best_match = None
    best_match_count = 0

    current_flags = set(current_red_flags)

    for item in memory:

        previous_flags = set(item["red_flags"])

        shared_flags = current_flags.intersection(
            previous_flags
        )

        if len(shared_flags) > best_match_count:

            best_match_count = len(shared_flags)

            best_match = {
                "previous_message": item["message"].strip(),
                "previous_risk_score": item["risk_score"],
                "previous_risk_level": item["risk_level"],
                "previous_scam_type": item["scam_type"],
                "shared_indicators": list(shared_flags)
            }

    if best_match is None or best_match_count == 0:

        return {
            "similar_case_found": False,
            "message": "No similar previous case found.",
            "matches": []
        }

    return {
        "similar_case_found": True,
        "message": "A similar previous case was found.",
        "matches": [best_match]
    }

def calculate_unified_risk(base_score, tool_results):
    final_score = base_score

    for result in tool_results:
        if result.get("tool") == "analyze_url":
            if result.get("result", {}).get("suspicious"):
                final_score += 10

        elif result.get("tool") == "check_threat_intelligence":
            threat = result.get("result", {})
            if threat.get("known_threat") is True:
                if threat.get("threat_level") == "HIGH":
                    final_score += 15
                elif threat.get("threat_level") == "MEDIUM":
                    final_score += 10

    return min(final_score, 100)


def aggregate_evidence(tool_results):
    evidence = {
        "url_evidence":[],
        "payment_evidence":[],
        "authority_evidence":[],
        "threat_intelligence":[],
        "overall_indicators":[]
    }

    for item in tool_results:
        tool_name = item.get("tool")
        result = item.get("result", {})

        if tool_name == "analyze_url":
            evidence["url_evidence"].append(result)

            if result.get("suspicious"):
                evidence["overall_indicators"].append(
                    "Suspicious URL detected"

                )
        elif  tool_name == "analyze_payment_request":
            evidence["payment_evidence"].append(result)

            if result.get("payment_request_detected"):
                evidence["overall_indicators"].append(
                    "Payment request detected"
                )

        elif tool_name == "verify_authority":
            evidence["authority_evidence"].append(result)

            if not result.get("verified"):
                evidence["overall_indicators"].append(
                    "Authority identity requires independent verification"
                )    

        elif tool_name == "check_threat_intelligence":
            evidence["threat_intelligence"].append(result)

            if result.get("known_threat"):
                evidence["overall_indicators"].append(
                    f"Known threat detected: {result.get('threat_level')}"
                )

    return evidence      


def make_agent_decision(
    message,
    red_flags,
    risk_score,
    risk_level,
    scam_type,
    evidence
):

    decision = {
        "decision":risk_level,
        "scam_type":scam_type,
        "risk_score":risk_score,
        "red_flags":red_flags,
        "evidence":evidence,
        "reason":"",
        "recommended_action":"",
    }

    if risk_level == "CRITICAL":
        decision["reason"] = (
            "Multiple high-risk indicators and supporting tool evidence "
            "suggest that this message may be a serious scam attempt."
        )

        decision["recommended_action"] = (
            "Do not click links, make payments, or share sensitive "
            "information. End the conversation and verify the claim "
            "through an official channel."
        )

    elif risk_level == "HIGH":
        decision["reason"] = (
            "The message contains significant suspicious indicators "
            "supported by the available analysis."
        )

        decision["recommended_action"] = (
            "Do not make payments or share sensitive information. "
            "Independently verify the sender and claim."
        )

    elif risk_level == "MEDIUM":
        decision["reason"] = (
            "The message contains some suspicious indicators that "
            "require additional verification."
        )

        decision["recommended_action"] = (
            "Be cautious and independently verify the sender "
            "before taking action."
        )    

    else:
        decision["reason"] = (
            "No immediate high-risk indicators were detected by "
            "the current analysis."
        )

        decision["recommended_action"] = (
            "Continue to use caution with unexpected requests "
            "and verify important claims."
        )

    return decision    


conversation_memory = []

def analyze_message(message):

    
    # 1. Detect red flags
    

    red_flags = detect_red_flags(message)

    
    # 2. Calculate base risk
    

    base_risk_score = calculate_risk_score(
        red_flags
    )

    
    # 3. Retrieve previous memory
    

    memory = get_memory()

    
    # 4. Retrieve only relevant memory
    

    relevant_memory = retrieve_relevant_memory(
        red_flags,
        memory
    )

    
    # 5. Create memory summary
    

    memory_summary = create_memory_summary(
        relevant_memory
    )

    
    # 6. Compare current case with memory
    

    memory_comparison = compare_with_memory(
        message,
        red_flags,
        relevant_memory
    )

    
    # 7. Prepare memory context for LLM
    

    memory_context = f"""
Previous Relevant Case Summary:

{memory_summary}

Memory Comparison:

{json.dumps(memory_comparison, indent=2)}
"""

    
    # 8. LLM analysis + tool execution
    

    llm_result = llm_analyze(
        message,
        memory_context
    )

    
    # 9. Aggregate tool evidence
    

    evidence = aggregate_evidence(
        llm_result["tool_results"]
    )

    
    # 10. Calculate final unified risk
    

    unified_risk_score = calculate_unified_risk(
        base_risk_score,
        llm_result["tool_results"]
    )

    
    # 11. Determine final risk level
    

    risk_level = get_risk_level(
        unified_risk_score
    )

    
    # 12. Detect scam type
    

    scam_type = detect_scam_type(
        red_flags
    )

    
    # 13. Generate safety recommendations
    

    recommendations = generate_safety_recommendations(
        risk_level,
        scam_type
    )

    
    # 14. Make final agent decision
    

    agent_decision = make_agent_decision(
        message,
        red_flags,
        unified_risk_score,
        risk_level,
        scam_type,
        evidence
    )

    
    # 15. Create final result
    

    result = {
        "red_flags": red_flags,
        "base_risk_score": base_risk_score,
        "risk_score": unified_risk_score,
        "risk_level": risk_level,
        "scam_type": scam_type,
        "recommendations": recommendations,
        "llm_analysis": llm_result["analysis"],
        "tool_results": llm_result["tool_results"],
        "selected_tools": llm_result["selected_tools"],
        "evidence": evidence,
        "agent_decision": agent_decision,
        "memory_comparison": memory_comparison
    }

    
    # 16. Save result to memory
    

    save_to_memory(
        message,
        result
    )

    return result

message = """This is an officer from the Cyber Crime Department.
Your Aadhaar is involved in a money laundering case.
You are under digital arrest.
Transfer ₹25,000 immediately."""


load_memory_from_mysql()

result = analyze_message(message)


print("\n========== AI Scam Detector ==========")

print("Red Flags:", result["red_flags"])
print("Base Risk Score:", result["base_risk_score"])
print("Final Unified Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])
print("Scam Type:", result["scam_type"])


print("\nSafety Recommendations:")

for recommendation in result["recommendations"]:
    print("-", recommendation)


print("\n========== LLM Analysis ==========")

print(result["llm_analysis"])

print("\n========== Tool Evidence ==========")

for tool_result in result["tool_results"]:
    print("-", tool_result["tool"], ":", tool_result["result"])

print("\n========== Agent Decisions ==========")
print("Selected Tools:", result["selected_tools"])   

print("\n========== Aggregated Evidence ==========")
print(json.dumps(result["evidence"], indent=2))

print("\n========== Final Agent Decision ==========")
print(json.dumps(result["agent_decision"], indent=2))

print("\n========== Retrieved Memory ==========")
memory = get_memory()
print(json.dumps(memory, indent=2))


print("\n\n========== SECOND MESSAGE TEST ==========")

message2 = """I am from Cyber Crime.
You are under digital arrest.
Transfer ₹25,000 immediately."""

result2 = analyze_message(message2)

print("\n========== SECOND MESSAGE RESULT ==========")
print(json.dumps(result2, indent=2))

print("\n========== FINAL MEMORY ==========")
print(json.dumps(get_memory(), indent=2))