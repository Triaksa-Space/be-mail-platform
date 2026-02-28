package config

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

var RedisClient *redis.Client

const lastActiveTTL = 15 * time.Minute
const lastActiveKeyPrefix = "user:lastactive:"

func InitRedis() {
	redisURL := viper.GetString("REDIS_URL")
	if redisURL == "" {
		log.Println("REDIS_URL not configured, heartbeat feature will be disabled")
		return
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("Warning: failed to parse REDIS_URL: %v - heartbeat feature disabled", err)
		return
	}

	RedisClient = redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := RedisClient.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: failed to connect to Redis: %v - heartbeat feature disabled", err)
		RedisClient = nil
		return
	}

	log.Println("Connected to Redis")
}

// SetLastActive stores the current timestamp for the given user in Redis.
func SetLastActive(userID int64) error {
	if RedisClient == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("%s%d", lastActiveKeyPrefix, userID)
	val := strconv.FormatInt(time.Now().UnixMilli(), 10)
	return RedisClient.Set(ctx, key, val, lastActiveTTL).Err()
}

// GetLastActive retrieves the last active timestamp for the given user from Redis.
// Returns nil if the key does not exist or Redis is unavailable.
func GetLastActive(userID int64) *time.Time {
	if RedisClient == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("%s%d", lastActiveKeyPrefix, userID)
	val, err := RedisClient.Get(ctx, key).Result()
	if err != nil {
		return nil
	}

	ms, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return nil
	}

	t := time.UnixMilli(ms)
	return &t
}
