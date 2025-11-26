"""CWE context enrichment from collect.json database."""

import json
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class CWEEnricher:
    """Enrich entries with CWE descriptions and context."""

    def __init__(self, cwe_database_path: str = "collect.json"):
        """Initialize CWE enricher.

        Args:
            cwe_database_path: Path to collect.json file
        """
        self.cwe_database_path = Path(cwe_database_path)
        self.cwe_data = self._load_cwe_database()

    def _load_cwe_database(self) -> Dict:
        """Load CWE database from collect.json.

        Returns:
            Dictionary mapping CWD IDs to CWE information
        """
        if not self.cwe_database_path.exists():
            logger.warning(f"CWE database not found at {self.cwe_database_path}")
            return {}

        try:
            with open(self.cwe_database_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logger.info(f"Loaded CWE database with {len(data)} entries")
                return data
        except Exception as e:
            logger.error(f"Failed to load CWE database: {e}")
            return {}

    def get_cwe_info(self, cwe_id: str) -> Dict[str, str]:
        """Get CWE information for a given CWE ID.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")

        Returns:
            Dictionary with CWE information (id, name, description)
        """
        # Normalize CWE ID
        if not cwe_id:
            return {
                'id': 'Unknown',
                'name': 'Unknown Weakness',
                'description': 'No CWE information available'
            }

        cwe_id = cwe_id.upper().strip()
        if not cwe_id.startswith('CWE-'):
            cwe_id = f'CWE-{cwe_id}'

        # Extract CWE number
        try:
            cwe_num = cwe_id.split('-')[1]
        except IndexError:
            logger.warning(f"Invalid CWE ID format: {cwe_id}")
            return {
                'id': cwe_id,
                'name': 'Invalid CWE ID',
                'description': 'Invalid CWE ID format'
            }

        # Search in database (CWE data is organized by CWD IDs)
        # We need to search through CWDs to find the CWE
        for cwd_id, cwd_data in self.cwe_data.items():
            if 'cwes' in cwd_data:
                for cwe in cwd_data['cwes']:
                    if cwe.get('id') == cwe_id or cwe.get('id') == cwe_num:
                        return {
                            'id': cwe_id,
                            'name': cwe.get('name', 'Unknown'),
                            'description': cwe.get('description', 'No description available'),
                            'cwd_id': cwd_id,
                            'cwd_name': cwd_data.get('name', '')
                        }

        # If not found in database, return basic info
        logger.debug(f"CWE {cwe_id} not found in database")
        return {
            'id': cwe_id,
            'name': f'CWE-{cwe_num}',
            'description': f'See https://cwe.mitre.org/data/definitions/{cwe_num}.html'
        }

    def enrich_entry(self, entry: Dict) -> Dict:
        """Enrich an entry with CWE information.

        Args:
            entry: Entry dictionary with CWE field

        Returns:
            Entry with added cwe_info field
        """
        cwe_id = entry.get('CWE', '')
        entry['cwe_info'] = self.get_cwe_info(cwe_id)

        # Also enrich other_CWEs if present
        if 'other_CWEs' in entry and entry['other_CWEs']:
            entry['other_cwe_info'] = [
                self.get_cwe_info(cwe) for cwe in entry['other_CWEs']
            ]

        return entry

    def get_cwe_description_summary(self, cwe_id: str, max_length: int = 200) -> str:
        """Get a summarized CWE description.

        Args:
            cwe_id: CWE identifier
            max_length: Maximum description length

        Returns:
            Summarized description
        """
        info = self.get_cwe_info(cwe_id)
        description = info.get('description', '')

        if len(description) <= max_length:
            return description

        # Truncate and add ellipsis
        return description[:max_length].rsplit(' ', 1)[0] + '...'
