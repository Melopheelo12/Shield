"""Les tests d'intégration arrivent au sprint 1 (tâches S1-05 et S1-06).

Ce fichier existe pour que le job `integration` de la CI ne tombe pas sur un
répertoire vide. Voir README.md pour la liste de ce qui doit être couvert.
"""

import pytest


@pytest.mark.skip(reason="À écrire au sprint 1, avec le branchement PostgreSQL")
def test_chaine_complete_ingestion_vers_verdict():
    raise NotImplementedError
