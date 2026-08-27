from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class CategoryResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: str
    icon: str
    color: str
    article_count: int = 0

class ArticleCreate(BaseModel):
    title: str
    type: str
    category_id: Optional[str] = None
    tags: List[str] = []
    summary: str = ""
    content: str
    difficulty: str = "beginner"

class ArticleResponse(BaseModel):
    id: str
    title: str
    slug: str
    type: str
    status: str
    category: Optional[CategoryResponse] = None
    tags: List[str]
    summary: str
    author: str
    view_count: int
    helpful_count: int
    published_at: Optional[str] = None
    created_at: str

class PatternResponse(BaseModel):
    id: str
    name: str
    description: str
    vulnerability_types: List[str]
    languages: List[str]
    confidence: float
    success_rate: float
    times_applied: int

class AttackPatternResponse(BaseModel):
    id: str
    mitre_id: str
    name: str
    tactic: str
    platforms: List[str]
    description: str

@router.get("/categories", response_model=List[CategoryResponse])
async def list_categories():
    return []

@router.post("/categories", response_model=CategoryResponse)
async def create_category(name: str, slug: str, description: str = "", icon: str = "", color: str = ""):
    return CategoryResponse(
        id="new-category-id",
        name=name,
        slug=slug,
        description=description,
        icon=icon,
        color=color,
        article_count=0,
    )

@router.get("/articles", response_model=List[ArticleResponse])
async def list_articles(
    category_id: Optional[str] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
):
    return []

@router.post("/articles", response_model=ArticleResponse, status_code=201)
async def create_article(article: ArticleCreate):
    return ArticleResponse(
        id="new-article-id",
        title=article.title,
        slug=article.title.lower().replace(" ", "-"),
        type=article.type,
        status="draft",
        category=None,
        tags=article.tags,
        summary=article.summary,
        author="current-user",
        view_count=0,
        helpful_count=0,
        created_at=datetime.utcnow().isoformat(),
    )

@router.get("/articles/{article_id}", response_model=ArticleResponse)
async def get_article(article_id: str):
    raise HTTPException(status_code=404, detail="Article not found")

@router.patch("/articles/{article_id}", response_model=ArticleResponse)
async def update_article(article_id: str, update: dict):
    raise HTTPException(status_code=404, detail="Article not found")

@router.post("/articles/{article_id}/publish")
async def publish_article(article_id: str):
    return {"message": "Article published"}

@router.post("/articles/{article_id}/feedback")
async def add_feedback(article_id: str, rating: int, comment: str = ""):
    return {"message": "Feedback added"}

@router.get("/patterns", response_model=List[PatternResponse])
async def list_patterns(vuln_type: Optional[str] = None, language: Optional[str] = None):
    return []

@router.get("/attack-patterns", response_model=List[AttackPatternResponse])
async def list_attack_patterns(tactic: Optional[str] = None):
    return []

@router.get("/search")
async def search_knowledge(q: str, limit: int = 10):
    return {"results": []}