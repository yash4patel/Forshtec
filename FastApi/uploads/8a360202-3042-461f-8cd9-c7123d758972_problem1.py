# import copy

# a = [1, 2, 3, 5, 7]

# result = copy.copy(a)

# print(result)
# #[1, 2, 3, 5, 7]
# print(a)
# #[1, 2, 3, 5, 7]

# result[0] = 3


# print(result)
# #[3, 2, 3, 5, 7]

# print(a) -wrong
# #[3, 2, 3, 5, 7]

# b = [2, 3, 6, [7, 9]]
# result2 = copy.copy(b)
# print(b)
# #[2, 3, 6, [7, 9]]
# print(result2)
# #[2, 3, 6, [7, 9]]


# result2[0] = 1 

# print(result2)
# #[1, 3, 6, [7, 9]]

# print(b)
# #[1, 3, 6, [7, 9]]

# result2[3][0] = 5


# print(result2)
# #[2, 3, 6, [5, 9]]

# print(b)
# #[2, 3, 6, [5, 9]]


# def valid_bracket(s):
#     stack =[]
#     brackets={')':'(','}':'{',']':'['}

#     for c in s:
#         if c in brackets.values():
#             stack.append(c) 
#         elif c in brackets:
#             if not stack or stack[-1]!=brackets[c]: 
#                 return False
#             stack.pop()

#     return True


# print(valid_bracket('[]'))
# print(valid_bracket('{(}' ))
# print(valid_bracket(')[]'))
# print(valid_bracket('()[]{}'))


# [7,1,5,3,6,4] [2,5]
# # [7,6,4,3,1] [-1,-1]

# def max_profit(prices):
#     min_price=prices[0]
#     min_index=0
#     buy_index=0
#     sell_index=0
#     profit=0

#     for i in range(1,len(prices)):
#         if prices[i]-min_price>profit:
#             profit=prices[i]-min_price
#             buy_index=min_index
#             sell_index=i

#         if prices[i]<min_price:
#             min_price=prices[i]
#             min_index=i
#     if profit ==0:
#         return [-1,-1]
    
#     return [buy_index+1,sell_index+1]


# print(max_profit([7,1,5,3,6,4]))
# print(max_profit([7,6,4,3,1]))
# print(max_profit([1,4]))


# demo.py
# p=[k,v for i in [1,2,3]]

# response time 1 min
# reduce to 10s

# - netwrok
# - caching
# - last 60 min
# - cehck most frquent request store cach
# - client caching

# - selected prefetche
# -rate limiting
# __main__
# __iniy__

# mangaling name
# what is the sequence for middleware ehich sequence they are executing
# how python manage.py makemigrate do the changes
# what is inside migrate file what is the parenet class 
# what is middle ware
# which on would be better to implement authentication in middleware or in decorator
# what is incapsulated class
# can we access private variable to the another class
# how db track the changes in django
# redis
# 