#pragma once

#ifdef __cplusplus
extern "C" {
#endif
  /*Return 1 if lhs == rhs and 0 otherwise*/
  int32_t obs_int32_eq(int32_t lhs, int32_t rhs);

  /* Return 1 if lhs < rhs and 0 otherwise*/
  int32_t obs_int32_lt(int32_t lhs, int32_t rhs);

  /*Return rhs if sel = 0 and lhs otherwise*/
  int32_t obs_int32_select(int32_t lhs, int32_t rhs, int32_t sel);

  /* Return base^exp*/
  int32_t obs_int32_pow(int32_t base, int32_t exp);
#ifdef __cplusplus
}
#endif

int32_t obs_int32_neq(int32_t lhs, int32_t rhs)
{
    return 1 ^ obs_int32_eq(lhs, rhs);
}

 /*Return 1 if lhs > rhs and 0 otherwise*/
int32_t obs_int32_gt(int32_t lhs, int32_t rhs) {
    return obs_int32_lt(rhs, lhs);
}

/*Return 1 if lhs >= rhs and 0 otherwise*/
int32_t obs_int32_ge(int32_t lhs, int32_t rhs) {
    return 1 ^ obs_int32_lt(lhs, rhs);
}

/*Return 1 if lhs <= rhs and 0 otherwise*/
int32_t obs_int32_le(int32_t lhs, int32_t rhs) {
    return 1 ^ obs_int32_gt(rhs, lhs);
}

/*Return 1 if lhs > rhs, -1 if lhs < rhs and 0 otherwise*/
int32_t obs_int32_cmp(int32_t lhs, int32_t rhs) {
    return obs_int32_gt(lhs, rhs) | -obs_int32_lt(lhs, rhs);
}
