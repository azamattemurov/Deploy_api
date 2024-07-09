from django.urls import path

from post.views import PostListView, PostCommentListView, PostCreateView, PostCommentCreateView, PostLikeAPIView, \
    CommentLikeAPIView, PostUpdateAPIView, CommentUpdateAPIView, UserPostListView, UserLikedPostsView, \
    UserLikedCommentsView, PostDeleteAPIView

app_name = 'post'

urlpatterns = [
    path('list/', PostListView.as_view(), name='list'),
    path('myself/', UserPostListView.as_view(), name='myself'),
    path('mylike/', UserLikedPostsView.as_view(), name='my_like'),
    path('create/', PostCreateView.as_view(), name='create'),
    path('<int:pk>/like/', PostLikeAPIView.as_view(), name='like'),
    path('<int:pk>/update/', PostUpdateAPIView.as_view(), name='update'),
    path('<int:pk>/delete/', PostDeleteAPIView.as_view(), name='delete'),

    path('mycomment/', UserLikedCommentsView.as_view(), name='my_comment'),
    path('<int:pk>/comment/', PostCommentListView.as_view(), name='comments-list'),
    path('<int:pk>/comment/create/', PostCommentCreateView.as_view(), name='comment-create'),
    path('<int:pk>/comment/like/', CommentLikeAPIView.as_view(), name='comment-like'),
    path('<int:pk>/comment/update/', CommentUpdateAPIView.as_view(), name='comment-update'),
]