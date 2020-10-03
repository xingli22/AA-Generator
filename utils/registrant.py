from pprint import pprint


def register(registration_file, service_name):
    file = open(registration_file, 'a+')
    file.write(service_name + '\n')
    file.close()


def clean_registration(registration_file):
    file = open(registration_file, 'w')
    file.write('')
    file.close()


def get_registration(registration_file):
    file = open(registration_file, 'r')
    registration = file.read().split()
    # pprint(registration)
    return registration
