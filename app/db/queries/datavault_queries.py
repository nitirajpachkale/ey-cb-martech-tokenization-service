from sqlalchemy import text

MERGE_DATAVAULT = text("""
MERGE INTO SCM_TKN.tbl_datavault d
USING (
    SELECT 
        :referenceid AS referenceid,
        :referencetoken AS referencetoken,
        :tokenjson AS tokenjson,
        :encjson AS encjson
    FROM dual
) s
ON (d.referenceid = s.referenceid)
WHEN MATCHED THEN
    UPDATE SET 
        d.referencetoken = s.referencetoken,
        d.tokenjson = s.tokenjson,
        d.encjson = s.encjson,
        d.modifydate = CURRENT_TIMESTAMP
WHEN NOT MATCHED THEN
    INSERT (
        referenceid,
        referencetoken,
        tokenjson,
        encjson,
        adddate
    )
    VALUES (
        s.referenceid,
        s.referencetoken,
        s.tokenjson,
        s.encjson,
        CURRENT_TIMESTAMP
    )
""")

def upsert_datavault_bulk(db, payload: list):
    db.execute(MERGE_DATAVAULT, payload)