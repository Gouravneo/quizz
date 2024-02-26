from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.

COURSE_CHOICES = (
        (0, _('Product Design')),
        (1, _('Frontend')),
        (2, _('Backend')),
    )

# QUESTION MODEL-------------------------------------------------------------------------------
class Question(models.Model):
    course = models.IntegerField(choices=COURSE_CHOICES, default=0, verbose_name=_('Course'))
    question = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True, verbose_name=_('Date Created'))
    question_updated= models.DateTimeField(verbose_name=_('Last Updated'), auto_now=True)
    is_active = models.BooleanField(default=False, verbose_name=_('Active Status'))

    def __str__(self):
        return self.question

    class Meta:
        verbose_name = _('Question')
        verbose_name_plural = _('Questions')
        ordering = ['id']

# ANSWER MODEL------------------------------------------------------------------------------------
class Answer(models.Model):
    question = models.ForeignKey(Question, related_name='answer', on_delete=models.DO_NOTHING)
    answer_text = models.CharField(max_length=255, verbose_name=_('Answer Text'))
    is_right = models.BooleanField(default=False)
    answer_updated = models.DateTimeField(verbose_name=_('Last Updated'), auto_now=True)

    def __str__(self):
        return self.answer_text

    class Meta:
        verbose_name = _('Answer')
        verbose_name_plural = _('Answers')
        ordering = ['id']






