from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql="""
                    DO $$
                    BEGIN
                        IF to_regclass('public.users_user') IS NULL THEN
                            RETURN;
                        END IF;
                        IF to_regclass('public.users_user_role_36d76_idx') IS NOT NULL
                           AND to_regclass('public.users_user_role_36d76d_idx') IS NULL THEN
                            ALTER INDEX public.users_user_role_36d76_idx
                            RENAME TO users_user_role_36d76d_idx;
                        ELSIF to_regclass('public.users_user_role_36d76d_idx') IS NULL THEN
                            CREATE INDEX users_user_role_36d76d_idx
                            ON public.users_user (role);
                        END IF;
                    END $$;
                    """,
                    reverse_sql="""
                    DO $$
                    BEGIN
                        IF to_regclass('public.users_user_role_36d76d_idx') IS NOT NULL
                           AND to_regclass('public.users_user_role_36d76_idx') IS NULL THEN
                            ALTER INDEX public.users_user_role_36d76d_idx
                            RENAME TO users_user_role_36d76_idx;
                        END IF;
                    END $$;
                    """,
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
