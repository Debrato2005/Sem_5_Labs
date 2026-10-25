"""Menu/input adapter only. No cryptographic or database operations here."""
import json
from decimal import Decimal

from toolkit.util import ask, ask_choice, ask_list, ask_secret, menu


def run_ui(call, config):
    def session(role):
        password = ask_secret(f'{role} password: ')

        def action(name):
            req = {'role': role, 'password': password, 'action': name}
            fields = config['fields']
            if name == 'submit':
                req.update(id=ask('Record ID: '), values={field: ask(f'{field}: ') for field in fields})
            elif name == 'decrypt':
                req['id'] = ask('Record ID: ')
            elif name == 'search':
                req.update(field=ask_choice('Search field', ['id'] + list(fields)), value=ask('Value: '))
            elif name == 'aggregate':
                req['field'] = ask_choice('Number field', [f for f, kind in fields.items() if kind == 'number'])
                req['ids'] = ask_list('Record IDs, comma separated: ')
                op = ask_choice('Operation', ['sum', 'average', 'weighted'])
                if op == 'weighted':
                    req['weights'] = [int(w) for w in ask_list('Integer weights, same order: ')]
            result = call(req)
            print(json.dumps(result, indent=2))
            if name == 'aggregate' and result.get('ok') and op == 'average':
                print('Average =', Decimal(result['total']) / result['count'])

        menu(role, [(a, lambda a=a: action(a)) for a in config['roles'][role]])

    menu(config.get('title', 'SECURE RECORDS'),
         [(role, lambda role=role: session(role)) for role in config['roles']])
