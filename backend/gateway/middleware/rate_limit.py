
import redis.asyncio as redis
import time
from fastapi import Request, HTTPException
from backend.common.config import settings
from jose import jwt, JWTError

class RateLimiter:
    def __init__(self, capacity: int = 100, rate: float = 1.0):
        try:
            self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
            self.enabled = True
        except Exception:
            self.redis = None
            self.enabled = False
            print("Rate Limiter disabled: Redis connection failed")
        self.capacity = capacity
        self.rate = rate  # tokens per second

    async def __call__(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        # Identify user
        user_id = "anonymous"
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
                user_id = payload.get("sub", "anonymous")
            except JWTError:
                pass

        bucket_key = f"rate_limit:{user_id}"
        now = time.time()
        
        # Token bucket algorithm
        # Using a Lua script for atomicity
        lua_script = """
        local bucket_key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local requested = 1

        local bucket = redis.call('HMGET', bucket_key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or now

        local elapsed = math.max(0, now - last_refill)
        local refill_amount = elapsed * rate
        tokens = math.min(capacity, tokens + refill_amount)

        local allowed = false
        if tokens >= requested then
            tokens = tokens - requested
            allowed = true
        end

        redis.call('HMSET', bucket_key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', bucket_key, 3600)
        
        return allowed and 1 or 0
        """
        
        allowed = await self.redis.eval(lua_script, 1, bucket_key, self.capacity, self.rate, now)
        
        if not allowed:
            raise HTTPException(status_code=429, detail="Too Many Requests")
            
        response = await call_next(request)
        return response

rate_limiter = RateLimiter(capacity=100, rate=10) # 100 capacity, 10 tokens/sec refill
