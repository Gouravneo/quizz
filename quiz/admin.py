from django.contrib import admin
from . import models

# Register your models here.

class AnswerInlineModel(admin.TabularInline):
    model= models.Answer
    fields = [
        'answer_text',
        'is_right',
    ]

@admin.register(models.Question)

class QuestionAdmin(admin.ModelAdmin):
    fields = [
        'course',
        'question',
    ]
    list_display= [
        'course',
        'question',
        'question_updated',
    ]
    inlines = [
        AnswerInlineModel,
    ]

@admin.register(models.Answer)

class AnswerAdmin(admin.ModelAdmin):
    list_display= [
        'answer_text',
        'is_right',
        'question'
    ]