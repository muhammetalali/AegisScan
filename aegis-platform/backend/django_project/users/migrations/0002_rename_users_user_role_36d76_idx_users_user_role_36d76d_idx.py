from django.db import migrations, models


OLD_INDEX = 'users_user_role_36d76_idx'
NEW_INDEX = 'users_user_role_36d76d_idx'


def _postgresql_rename(apps, schema_editor, old_name, new_name):
    User = apps.get_model('users', 'User')
    old_index = schema_editor.quote_name(old_name)
    new_index = schema_editor.quote_name(new_name)
    with schema_editor.connection.cursor() as cursor:
        tables = schema_editor.connection.introspection.table_names(cursor)
        if User._meta.db_table not in tables:
            return
        constraints = schema_editor.connection.introspection.get_constraints(cursor, 'users_user')
        if new_name in constraints:
            return
        if old_name in constraints:
            schema_editor.execute(f'ALTER INDEX {old_index} RENAME TO {new_index}')
            return
    schema_editor.add_index(User, models.Index(fields=['role'], name=new_name))


def _portable_rebuild(apps, schema_editor, old_name, new_name):
    User = apps.get_model('users', 'User')
    table_name = User._meta.db_table
    with schema_editor.connection.cursor() as cursor:
        tables = schema_editor.connection.introspection.table_names(cursor)
        if table_name not in tables:
            return
        constraints = schema_editor.connection.introspection.get_constraints(cursor, table_name)
    if new_name in constraints:
        return
    if old_name in constraints:
        schema_editor.remove_index(User, models.Index(fields=['role'], name=old_name))
    schema_editor.add_index(User, models.Index(fields=['role'], name=new_name))


def rename_index_forward(apps, schema_editor):
    if schema_editor.connection.vendor == 'postgresql':
        _postgresql_rename(apps, schema_editor, OLD_INDEX, NEW_INDEX)
        return
    _portable_rebuild(apps, schema_editor, OLD_INDEX, NEW_INDEX)


def rename_index_backward(apps, schema_editor):
    if schema_editor.connection.vendor == 'postgresql':
        _postgresql_rename(apps, schema_editor, NEW_INDEX, OLD_INDEX)
        return
    _portable_rebuild(apps, schema_editor, NEW_INDEX, OLD_INDEX)


class Migration(migrations.Migration):
    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    rename_index_forward,
                    rename_index_backward,
                ),
            ],
            state_operations=[
                migrations.RenameIndex(
                    model_name='user',
                    old_name='users_user_role_36d76_idx',
                    new_name='users_user_role_36d76d_idx',
                ),
            ],
        ),
    ]
