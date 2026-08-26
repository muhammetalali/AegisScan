from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        custom_response = {
            'success': False,
            'error': {
                'code': response.status_code,
                'message': 'An error occurred',
                'details': response.data,
            }
        }
        response.data = custom_response
        return response

    if isinstance(exc, DjangoValidationError):
        return Response({
            'success': False,
            'error': {
                'code': status.HTTP_400_BAD_REQUEST,
                'message': 'Validation error',
                'details': exc.message_dict if hasattr(exc, 'message_dict') else str(exc),
            }
        }, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exc, IntegrityError):
        logger.exception('Database integrity error')
        return Response({
            'success': False,
            'error': {
                'code': status.HTTP_409_CONFLICT,
                'message': 'Resource conflict',
                'details': 'A resource with this identifier already exists',
            }
        }, status=status.HTTP_409_CONFLICT)

    logger.exception('Unhandled exception')
    return Response({
        'success': False,
        'error': {
            'code': status.HTTP_500_INTERNAL_SERVER_ERROR,
            'message': 'Internal server error',
            'details': 'An unexpected error occurred' if not settings.DEBUG else str(exc),
        }
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)