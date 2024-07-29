from itsdangerous import URLSafeTimedSerializer
from key import secret_key
def token(email,salt):
    serializer= URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email,salt=salt)
def token2(teamid,rid,salt,email=None):
    serializer= URLSafeTimedSerializer(secret_key)
    if email==None:
        return serializer.dumps({'rid':rid,'teamid':teamid},salt=salt)
    else:
        return serializer.dumps({'rid':rid,'teamid':teamid,'email':email},salt=salt)