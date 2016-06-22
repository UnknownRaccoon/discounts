def user_is_company(user):
    return user.company is not None

def user_important_data(user):
    return {'id': user.id, 'phone': user.username}