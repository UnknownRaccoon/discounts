def user_is_company(user):
    return hasattr(user, 'company')


def user_important_data(user):
    return {'id': user.id,
            'phone': user.username,
            'name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            }


def prepare_request(request, valid_method):
    if hasattr(request, '_post'):
        del request._post
        del request._files
    try:
        request.method = 'POST'
        request._load_post_and_files()
        request.method = valid_method
    except AttributeError:
        request.META['REQUEST_METHOD'] = 'POST'
        request._load_post_and_files()
        request.META['REQUEST_METHOD'] = valid_method
    return request.POST
