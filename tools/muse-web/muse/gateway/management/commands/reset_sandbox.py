import json
from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from muse.gateway.models import SandboxFile, SandboxEvent
from muse.gateway.sandbox import INITIAL_FILES, application_content, enabled, record
from muse.gateway.policy import Rejected


class Command(BaseCommand):
    help = 'Reset the disposable project. Use a new MUSE_SANDBOX_RUN_ID and restart before each run. Preserve audit history.'

    def add_arguments(self, parser):
        parser.add_argument('--fixtures', help='Optional operator-owned JSON mapping of all four resource paths to text content')

    def handle(self, *args, **options):
        try:
            enabled()
            files = INITIAL_FILES if not options['fixtures'] else json.loads(Path(options['fixtures']).read_text(encoding='utf-8'))
            if (not isinstance(files, dict) or set(files) != set(INITIAL_FILES)
                    or any(not isinstance(value, str) or len(value.encode('utf-8')) > 100000 for value in files.values())):
                raise CommandError('Fixtures must contain all four resource paths with bounded text values')
            application_content(files['/application'])
        except (Rejected, ValueError, OSError) as error:
            raise CommandError(str(error)) from error
        with transaction.atomic():
            if SandboxEvent.objects.filter(run_id=settings.SANDBOX_RUN_ID).exists():
                raise CommandError('Run ID already used. Set a new MUSE_SANDBOX_RUN_ID and restart before resetting.')
            before = dict(SandboxFile.objects.values_list('path', 'content'))
            for path, content in files.items():
                SandboxFile.objects.update_or_create(path=path, defaults={'content': content})
            record('operator', 'reset', files, {'before': before, 'after': files})
        self.stdout.write('Disposable project reset; audit history retained. No experiment was executed.')
