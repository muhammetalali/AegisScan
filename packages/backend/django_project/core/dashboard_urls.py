from django.urls import path

from .dashboard import (
    DashboardRecentValidationsView,
    DashboardRiskDistributionView,
    DashboardSummaryView,
    DashboardTrendsView,
)

urlpatterns = [
    path('summary', DashboardSummaryView.as_view(), name='dashboard-summary'),
    path('risk-distribution', DashboardRiskDistributionView.as_view(), name='dashboard-risk-distribution'),
    path('trends', DashboardTrendsView.as_view(), name='dashboard-trends'),
    path('recent-validations', DashboardRecentValidationsView.as_view(), name='dashboard-recent-validations'),
]
