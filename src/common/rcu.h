/*
 * rcu.h
 *
 *  Created on: Aug 28, 2018
 *      Author: anlang
 */

#ifndef RCU_H_
#define RCU_H_

#include <urcu-qsbr.h>

static inline void rcu_wait(void)
{
	synchronize_rcu();
}

static inline void rcu_get_obj()
{

}

static inline void rcu_put_obj()
{
	rcu_quiescent_state();
}

static inline void rcu_register_current_thread(void)
{
	rcu_register_thread();
}

static inline void rcu_unregister_current_thread(void)
{
	rcu_unregister_thread();
}

#endif /* RCU_H_ */
