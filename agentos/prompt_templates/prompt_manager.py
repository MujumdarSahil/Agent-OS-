"""
Prompt Manager - Manages prompt templates
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class PromptManager:
    """
    Prompt Manager - Manages prompt templates for agents.
    """
    
    def __init__(self):
        """Initialize Prompt Manager"""
        self.templates: Dict[str, str] = {}
        logger.info("PromptManager initialized")
    
    def register_template(self, name: str, template: str):
        """Register a prompt template"""
        self.templates[name] = template
        logger.info(f"Template registered: {name}")
    
    def get_template(self, name: str, variables: Optional[Dict[str, Any]] = None) -> str:
        """
        Get prompt template with variable substitution.
        
        Args:
            name: Template name
            variables: Variables to substitute
            
        Returns:
            Rendered template
        """
        template = self.templates.get(name, "")
        
        if variables:
            template = template.format(**variables)
        
        return template

