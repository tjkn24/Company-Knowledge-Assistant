"""rag/ — RAG service (standard, agentic, auto)"""
from rag.rag_service import (
    build_vector_store,
    get_retriever,
    retrieve_and_answer,
)

__all__ = ["build_vector_store", "get_retriever", "retrieve_and_answer"]
