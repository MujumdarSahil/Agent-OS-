"""
Tool Builder - Uses LLMClient to generate python tool stubs from descriptions
"""

import json
import logging
from typing import Dict, Any, Tuple
from pydantic import BaseModel, Field

from agentos.llm import LLMClient

logger = logging.getLogger(__name__)

class BuilderToolSchema(BaseModel):
    """Pydantic schema to validate generated tool details"""
    name: str = Field(..., description="Alphanumeric lowercase name of the tool, e.g. web_search")
    class_name: str = Field(..., description="CamelCase class name, e.g. WebSearch")
    description: str = Field(..., description="Clear description of what the tool does")
    run_code_stub: str = Field(..., description="Python code lines inside the run method, implementing the requested tool logic spec")


class ToolBuilder:
    """
    Constructs AgentOS BaseTool python stubs from descriptions using LLMClient.
    """
    
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def create_from_description(self, description: str) -> Tuple[Dict[str, Any], str]:
        """
        Sends a structured prompt to LLMClient.complete() requesting JSON with tool specs.
        Generates and returns (config_dict, python_stub_code).
        """
        system_prompt = (
            "You are an expert software developer designing tools for the AgentOS multi-agent framework.\n"
            "Given a tool request, return a JSON object with this exact schema:\n"
            "{\n"
            "  \"name\": \"snake_case_tool_name\",\n"
            "  \"class_name\": \"CamelCaseClassName\",\n"
            "  \"description\": \"One line description of the tool functionality\",\n"
            "  \"run_code_stub\": \"        # Implement logic here\\n        query = kwargs.get('query', '')\\n        return f'Results for: {query}'\"\n"
            "}\n"
            "Output ONLY raw JSON. Do NOT wrap it in markdown code blocks."
        )
        
        user_prompt = f"Tool description: {description}"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            res = self.llm_client.complete(messages=messages)
            content = res.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            content = self._clean_json(content)
            data = BuilderToolSchema.model_validate_json(content).model_dump()
        except Exception as e:
            logger.warning(f"Initial tool generation failed: {e}. Retrying once...")
            messages.append({"role": "assistant", "content": locals().get("content", "")})
            messages.append({
                "role": "user",
                "content": f"Your last response was not valid JSON or failed schema validation: {e}. Please return ONLY the raw JSON conforming to the schema."
            })
            res = self.llm_client.complete(messages=messages)
            content = res.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            content = self._clean_json(content)
            data = BuilderToolSchema.model_validate_json(content).model_dump()

        # Build python stub code
        py_code = (
            "\"\"\"\n"
            f"Custom Tool: {data['class_name']}\n"
            "\"\"\"\n\n"
            "from agentos.core.base import BaseTool\n\n"
            f"class {data['class_name']}(BaseTool):\n"
            f"    name: str = \"{data['name']}\"\n"
            f"    description: str = \"{data['description']}\"\n\n"
            "    def run(self, **kwargs) -> str:\n"
            "        # WARNING: The following run() method body is AI-drafted and needs human review before production use.\n"
            f"{data['run_code_stub']}\n"
        )
        
        config_dict = {
            "name": data["name"],
            "description": data["description"]
        }
        
        return config_dict, py_code

    def _clean_json(self, text: str) -> str:
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()
