# myproject/project_rate_limit.py
from django.core.cache import cache
from django.http import JsonResponse
import time

class ProjectRateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Rate limits (4/minute, 500/day)
        self.minute_limit = 4
        self.daily_limit = 500

    def __call__(self, request):
        # Skip rate limiting for admin URLs
        if request.path.startswith('/admin/'):
            return self.get_response(request)
            
        ip = self._get_client_ip(request)
        now = time.time()
        
        # Minute rate check
        minute_key = f"rate_minute_{ip}"
        minute_count = cache.get(minute_key, 0)
        
        # Daily rate check
        day_key = f"rate_day_{ip}"
        day_count = cache.get(day_key, 0)
        
        # Check limits
        if minute_count >= self.minute_limit:
            return JsonResponse({
                'error': 'Too many requests (4 per minute max)',
                'retry_after': 60 - int(now % 60)
            }, status=429)
            
        if day_count >= self.daily_limit:
            return JsonResponse({
                'error': 'Daily limit exceeded (500 requests max)',
                'retry_after': 86400 - int(now % 86400)
            }, status=429)
        
        # Increment counters
        cache.set(minute_key, minute_count + 1, 60)  # Expires in 60 seconds
        cache.set(day_key, day_count + 1, 86400)    # Expires in 24 hours
        
        return self.get_response(request)

    def _get_client_ip(self, request):
        """Get client IP from request"""
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        return xff.split(',')[0] if xff else request.META.get('REMOTE_ADDR')