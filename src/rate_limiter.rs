use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use std::num::NonZeroU32;

pub struct RateLimiter {
    #[allow(dead_code)]
    limiter: GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter").finish()
    }
}

impl RateLimiter {
    pub fn new(requests_per_second: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(requests_per_second).unwrap());
        Self {
            limiter: GovernorRateLimiter::direct(quota),
        }
    }

    pub async fn wait(&self) {
        self.limiter.until_ready().await;
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(10)
    }
}
