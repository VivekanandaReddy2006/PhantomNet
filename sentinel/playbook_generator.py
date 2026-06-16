import os
import logging
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logger = logging.getLogger("sentinel.playbook_generator")

class PlaybookGenerator:
    """
    Scaffold for dynamic incident response playbook generation.
    Configures a Jinja2 environment with FileSystemLoader pointing to the templates directory
    and renders playbooks based on provided context and attack patterns.
    """
    def __init__(self, templates_dir: str = None):
        if templates_dir is None:
            # Default to the 'templates' folder relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(current_dir, "templates")
        
        logger.info(f"Initializing PlaybookGenerator with templates directory: {templates_dir}")
        self.loader = FileSystemLoader(templates_dir)
        self.env = Environment(loader=self.loader, autoescape=False)

    def _select_template(self, attack_pattern: str) -> str:
        """
        Selects the appropriate Jinja2 template file based on the attack_pattern.
        """
        if not attack_pattern:
            raise ValueError("attack_pattern must be provided to select a template.")
            
        pattern = attack_pattern.lower().strip()
        
        # Mappings matching standard attack patterns to templates
        if "brute_force" in pattern or "brute-force" in pattern or "failed_login" in pattern:
            return "brute_force_response.yaml.j2"
        elif "port_scan" in pattern or "port-scan" in pattern or "scan" in pattern:
            return "port_scan_response.yaml.j2"
        elif "credential_reuse" in pattern or "credential-reuse" in pattern or "honeytoken" in pattern:
            return "credential_reuse_response.yaml.j2"
        elif "distributed_attack" in pattern or "distributed-attack" in pattern or "distributed" in pattern:
            return "distributed_attack_response.yaml.j2"
        else:
            # Default fallback mapping
            logger.warning(f"Unknown attack pattern: '{attack_pattern}'. Defaulting to pattern-based template name.")
            return f"{pattern}_response.yaml.j2"

    def generate(self, context_data: Dict[str, Any]) -> str:
        """
        Generates a playbook YAML string by selecting a template based on the 
        'attack_pattern' parameter in context_data and rendering it.
        """
        attack_pattern = context_data.get("attack_pattern")
        if not attack_pattern:
            raise ValueError("context_data must contain an 'attack_pattern' key.")

        template_name = self._select_template(attack_pattern)
        logger.info(f"Selected template: {template_name} for attack pattern: {attack_pattern}")

        try:
            template = self.env.get_template(template_name)
        except TemplateNotFound:
            logger.error(f"Template not found: {template_name}")
            raise FileNotFoundError(f"Template '{template_name}' not found for attack pattern '{attack_pattern}'")

        try:
            rendered_yaml = template.render(context_data)
            return rendered_yaml
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            raise
