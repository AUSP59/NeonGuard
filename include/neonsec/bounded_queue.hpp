// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

namespace neonsec {

template<typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t cap): cap_(cap) {}

    void close(){
        std::unique_lock<std::mutex> lk(mu_);
        closed_ = true;
        cv_.notify_all();
    }

    bool push(T v){
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&]{ return closed_ || q_.size() < cap_; });
        if (closed_) return false;
        q_.push(std::move(v));
        cv_.notify_all();
        return true;
    }

    std::optional<T> pop(){
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&]{ return closed_ || !q_.empty(); });
        if (q_.empty()) return std::nullopt;
        T v = std::move(q_.front());
        q_.pop();
        cv_.notify_all();
        return v;
    }

private:
    size_t cap_;
    std::queue<T> q_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool closed_ = false;
};

} // namespace neonsec
