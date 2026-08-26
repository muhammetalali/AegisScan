from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class KnowledgeCategory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=100)
    slug = models.SlugField(_('slug'), max_length=120, unique=True)
    description = models.TextField(_('description'), blank=True)
    icon = models.CharField(_('icon'), max_length=50, blank=True)
    color = models.CharField(_('color'), max_length=7, blank=True)  # Hex color
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    order = models.PositiveIntegerField(_('order'), default=0)
    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Knowledge Category')
        verbose_name_plural = _('Knowledge Categories')
        ordering = ['order', 'name']

    def __str__(self):
        return self.name


class KnowledgeArticle(models.Model):
    class Type(models.TextChoices):
        BEST_PRACTICE = 'best_practice', _('Best Practice')
        REMEDIATION_GUIDE = 'remediation_guide', _('Remediation Guide')
        SECURITY_POLICY = 'security_policy', _('Security Policy')
        LESSON_LEARNED = 'lesson_learned', _('Lesson Learned')
        ATTACK_PATTERN = 'attack_pattern', _('Attack Pattern')
        DEFENSE_GAP = 'defense_gap', _('Defense Gap')
        TOOL_GUIDE = 'tool_guide', _('Tool Guide')
        FAQ = 'faq', _('FAQ')
        TEMPLATE = 'template', _('Template')

    class Status(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        PUBLISHED = 'published', _('Published')
        ARCHIVED = 'archived', _('Archived')
        UNDER_REVIEW = 'under_review', _('Under Review')

    class Difficulty(models.TextChoices):
        BEGINNER = 'beginner', _('Beginner')
        INTERMEDIATE = 'intermediate', _('Intermediate')
        ADVANCED = 'advanced', _('Advanced')
        EXPERT = 'expert', _('Expert')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(_('title'), max_length=300)
    slug = models.SlugField(_('slug'), max_length=320, unique=True)
    type = models.CharField(_('type'), max_length=30, choices=Type.choices)
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.DRAFT)
    difficulty = models.CharField(_('difficulty'), max_length=20, choices=Difficulty.choices, default=Difficulty.BEGINNER)
    category = models.ForeignKey(KnowledgeCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name='articles')
    tags = models.JSONField(_('tags'), default=list, blank=True)

    # Content
    summary = models.TextField(_('summary'), blank=True)
    content = models.TextField(_('content'))  # Markdown
    content_html = models.TextField(_('content HTML'), blank=True)

    # Metadata
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='authored_articles')
    reviewers = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='reviewed_articles', blank=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_articles')
    approved_at = models.DateTimeField(_('approved at'), blank=True, null=True)

    # Engagement
    view_count = models.PositiveIntegerField(_('view count'), default=0)
    helpful_count = models.PositiveIntegerField(_('helpful count'), default=0)
    not_helpful_count = models.PositiveIntegerField(_('not helpful count'), default=0)

    # Versioning
    version = models.CharField(_('version'), max_length=20, default='1.0')
    previous_version = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='next_version')
    change_log = models.TextField(_('change log'), blank=True)

    # SEO
    meta_title = models.CharField(_('meta title'), max_length=200, blank=True)
    meta_description = models.TextField(_('meta description'), blank=True)

    # Relations
    related_articles = models.ManyToManyField('self', symmetrical=False, blank=True, related_name='related_to')
    related_vulnerabilities = models.ManyToManyField('vulnerabilities.Vulnerability', blank=True, related_name='knowledge_articles')
    related_controls = models.ManyToManyField('compliance.ComplianceControl', blank=True, related_name='knowledge_articles')

    published_at = models.DateTimeField(_('published at'), blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Knowledge Article')
        verbose_name_plural = _('Knowledge Articles')
        ordering = ['-published_at', '-created_at']
        indexes = [
            models.Index(fields=['status', 'category']),
            models.Index(fields=['tags']),
            models.Index(fields=['author']),
        ]

    def __str__(self):
        return self.title


class KnowledgeArticleView(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    article = models.ForeignKey(KnowledgeArticle, on_delete=models.CASCADE, related_name='views')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='article_views', null=True, blank=True)
    ip_address = models.GenericIPAddressField(_('IP address'))
    user_agent = models.TextField(_('user agent'), blank=True)
    duration = models.PositiveIntegerField(_('duration (seconds)'), default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Article View')
        verbose_name_plural = _('Article Views')
        ordering = ['-created_at']


class KnowledgeArticleFeedback(models.Model):
    class Rating(models.IntegerChoices):
        NOT_HELPFUL = 1, _('Not Helpful')
        NEUTRAL = 2, _('Neutral')
        HELPFUL = 3, _('Helpful')
        VERY_HELPFUL = 4, _('Very Helpful')
        EXCELLENT = 5, _('Excellent')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    article = models.ForeignKey(KnowledgeArticle, on_delete=models.CASCADE, related_name='feedbacks')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='article_feedbacks')
    rating = models.IntegerField(_('rating'), choices=Rating.choices)
    comment = models.TextField(_('comment'), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Article Feedback')
        verbose_name_plural = _('Article Feedbacks')
        unique_together = ['article', 'user']
        ordering = ['-created_at']


class RemediationPattern(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'))
    vulnerability_types = models.JSONField(_('vulnerability types'), default=list)  # CWE IDs, categories
    severity_range = models.JSONField(_('severity range'), default=list)  # ['critical', 'high', 'medium']
    code_patterns = models.JSONField(_('code patterns'), default=list)  # Regex patterns to match
    fix_template = models.TextField(_('fix template'))  # Template with placeholders
    fix_examples = models.JSONField(_('fix examples'), default=list)
    languages = models.JSONField(_('languages'), default=list)  # ['python', 'javascript', 'java', ...]
    frameworks = models.JSONField(_('frameworks'), default=list)  # ['django', 'express', 'spring', ...]
    confidence = models.FloatField(_('confidence'), default=0.8)
    success_rate = models.FloatField(_('success rate'), default=0)
    times_applied = models.PositiveIntegerField(_('times applied'), default=0)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_patterns')
    is_verified = models.BooleanField(_('verified'), default=False)
    verified_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_patterns')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Remediation Pattern')
        verbose_name_plural = _('Remediation Patterns')
        ordering = ['-confidence', '-success_rate']

    def __str__(self):
        return self.name


class AttackPattern(models.Model):
    class Tactic(models.TextChoices):
        RECONNAISSANCE = 'reconnaissance', _('Reconnaissance')
        RESOURCE_DEVELOPMENT = 'resource_development', _('Resource Development')
        INITIAL_ACCESS = 'initial_access', _('Initial Access')
        EXECUTION = 'execution', _('Execution')
        PERSISTENCE = 'persistence', _('Persistence')
        PRIVILEGE_ESCALATION = 'privilege_escalation', _('Privilege Escalation')
        DEFENSE_EVASION = 'defense_evasion', _('Defense Evasion')
        CREDENTIAL_ACCESS = 'credential_access', _('Credential Access')
        DISCOVERY = 'discovery', _('Discovery')
        LATERAL_MOVEMENT = 'lateral_movement', _('Lateral Movement')
        COLLECTION = 'collection', _('Collection')
        COMMAND_AND_CONTROL = 'command_and_control', _('Command and Control')
        EXFILTRATION = 'exfiltration', _('Exfiltration')
        IMPACT = 'impact', _('Impact')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mitre_id = models.CharField(_('MITRE ID'), max_length=20, unique=True)  # T1234
    name = models.CharField(_('name'), max_length=200)
    tactic = models.CharField(_('tactic'), max_length=30, choices=Tactic.choices)
    description = models.TextField(_('description'))
    platforms = models.JSONField(_('platforms'), default=list)  # ['Linux', 'Windows', 'macOS', 'Cloud', 'Network']
    permissions_required = models.JSONField(_('permissions required'), default=list)
    data_sources = models.JSONField(_('data sources'), default=list)
    detection_rules = models.JSONField(_('detection rules'), default=list)  # Sigma, YARA, etc.
    mitigation_strategies = models.JSONField(_('mitigation strategies'), default=list)
    related_techniques = models.JSONField(_('related techniques'), default=list)
    examples = models.JSONField(_('examples'), default=list)
    references = models.JSONField(_('references'), default=list)
    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Attack Pattern')
        verbose_name_plural = _('Attack Patterns')
        ordering = ['mitre_id']

    def __str__(self):
        return f"{self.mitre_id}: {self.name}"