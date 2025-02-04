package com.grey.springbootsecurity.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.*;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;


@Component
public class RedisCache {

    @Autowired
    public RedisTemplate redisTemplate;

    /**
     * 缓存基本对象，Integer,String,实体类等
     * @param key  缓存的键
     * @param value 缓存的值
     * @param <T>
     */
    public <T> void setCacheObject(final String key, final T value){
        redisTemplate.opsForValue().set(key,value);
    }

    /**
     * 缓存基本对象，Integer,String,实体类等
     * @param key  缓存的键
     * @param value 缓存的值
     * @param timeout 时间
     * @param timeUnit 时间单位
     * @param <T>
     */
    public <T> void setCacheObject(final String key , final T value , final Integer timeout, final TimeUnit timeUnit){
        redisTemplate.opsForValue().set(key,value,timeout,timeUnit);
    }

    public boolean expire(final String key ,final long timeout){
        return expire(key,timeout,TimeUnit.SECONDS);
    }

    public boolean expire(final String key , final long timeout, final TimeUnit unit){
        return  redisTemplate.expire(key,timeout,unit);
    }

    public <T> T getCacheObject (final String key){
        ValueOperations<String ,T> operation = redisTemplate.opsForValue();
        return operation.get(key);
    }

    public boolean deleteObject(final String key){
        return redisTemplate.delete(key);
    }

    public long deleteObject(final Collection collection){
        return redisTemplate.delete(collection);
    }

    public <T> long setCacheList(final String key ,final List<T> dataList){
        Long count = redisTemplate.opsForList().rightPushAll(key, dataList);
        return count == null ? 0: count;
    }

    /**
     * 获取缓存的list对象
     * @param key
     * @return
     * @param <T>
     */
    public <T> List<T> getCacheList(final String key){
        return redisTemplate.opsForList().range(key,0,-1);
    }

    /**
     * 缓存set
     * @param key
     * @param dataSet
     * @return
     * @param <T>
     */
    public <T>BoundSetOperations<String,T> setCacheSet(final String key, final Set<T> dataSet){
        BoundSetOperations<String ,T> setOperations = redisTemplate.boundSetOps(key);
        Iterator<T> it = dataSet.iterator();
        while (it.hasNext()){
            setOperations.add(it.next());
        }
        return setOperations;
    }

    /**
     * 获取缓存的set
     * @param key
     * @return
     * @param <T>
     */
    public <T> Set <T> getCacheSet(final String key){
        return redisTemplate.opsForSet().members(key);
    }

    /**
     * 设置缓存的map
     * @param key
     * @param dataMap
     * @param <T>
     */
    public <T> void setCacheMap(final String key , final Map<String,T> dataMap){
        if(dataMap !=null){
            redisTemplate.opsForHash().putAll(key,dataMap);
        }
    }

    public <T> Map<String ,T> getCacheMap(final String key){
        return redisTemplate.opsForHash().entries(key);
    }

    public <T> void setCacheMapValue(final String key,final String hkey , final T value){
        redisTemplate.opsForHash().put(key,hkey,value);
    }

    public <T> T getCacheMapValue(final String key, final String hkey){
        HashOperations<String,String,T> opsForHash = redisTemplate.opsForHash();
        return opsForHash.get(key,hkey);
    }

    public void delCacheMapValue(final String key,final String hkey){
        HashOperations hashOperations = redisTemplate.opsForHash();
        hashOperations.delete(key,hkey);
    }

    public <T> List<T> getMultiCacheMapValue(final String key,final Collection<Object> hkeys){
        return redisTemplate.opsForHash().multiGet(key,hkeys);
    }

    public Collection<String> keys(final String pattern){
        return redisTemplate.keys(pattern);
    }

}
