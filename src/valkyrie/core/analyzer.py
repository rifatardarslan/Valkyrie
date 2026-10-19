from abc import ABC, abstractmethod
from typing import Any, Dict

class AbstractAnalyzer(ABC):
    """Base interface for all Valkyrie analyzers (Static/Dynamic)."""

    @abstractmethod
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform analysis on the given file.
        
        Args:
            file_path: Absolute or relative path to the suspect file.
            
        Returns:
            Dictionary containing analysis results.
        """
        pass

    @abstractmethod
    def report(self) -> str:
        """
        Generate a formatted report of the analysis.
        """
        pass
