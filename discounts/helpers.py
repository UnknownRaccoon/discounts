def user_is_company(user):
    return user.company is not None


def user_important_data(user):
    return {'id': user.id, 'phone': user.username, 'name': user.first_name, 'surname': user.last_name}
